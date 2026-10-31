import json

from fastapi.testclient import TestClient

from tests.conftest import FIXTURES
from tracii import cli, gate
from tracii.api import main as api
from tracii.detect.static_rules import analyze_package
from tracii.evidence.schema import CheckRun, ScanSource, Severity
from tracii.export import sarif, sbom
from tracii.intake.npm_registry import load_local_package
from tracii.pipeline import STORE, run_scan


def scan_demo(demo_project, mock_http):
    rec = STORE.new()
    return rec, run_scan(rec, ScanSource(kind="fixture", label="t"), *demo_project, http=mock_http(), deep_limit=0)


# ---------- SARIF ----------

def test_sarif_results_point_at_lockfile_lines(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    lock = demo_project[1].decode()
    doc = sarif.to_sarif(scan, lock, "app/package-lock.json")
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "Tracii"
    assert len(run["results"]) == len(scan.findings)
    res = next(r for r in run["results"] if r["properties"]["package"] == "lodash")
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/package-lock.json"
    assert '"node_modules/lodash"' in lock.splitlines()[loc["region"]["startLine"] - 1]
    assert res["level"] == "error" and res["properties"]["security-severity"] == "8.0"
    rule = run["tool"]["driver"]["rules"][res["ruleIndex"]]
    assert rule["id"] == res["ruleId"] == "GHSA-35jh-r3h4-6jhm" and "known_vulnerability" in rule["properties"]["tags"]
    assert len({r["partialFingerprints"]["traciiFinding/v1"] for r in run["results"]}) == len(run["results"])


def test_sarif_unknown_severity_gets_no_invented_score(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    scan.findings[0].severity = Severity.UNKNOWN
    res = sarif.to_sarif(scan)["runs"][0]["results"][0]
    assert "security-severity" not in res["properties"] and res["level"] == "warning"


def test_sarif_failed_check_marks_run_unsuccessful(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    scan.checks.append(CheckRun(name="guarddog", status="failed", detail="docker missing"))
    inv = sarif.to_sarif(scan)["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert any(n["level"] == "error" and "guarddog" in n["message"]["text"] for n in inv["toolExecutionNotifications"])


def test_sarif_malicious_evidence_without_untrusted_snippets(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    scan.findings = analyze_package(load_local_package(FIXTURES / "packages" / "fake-exfil"))
    res = next(r for r in sarif.to_sarif(scan)["runs"][0]["results"] if r["ruleId"] == "TRACII-CHAIN-EXFIL")
    assert res["properties"]["category"] == "malicious_indicator"
    assert all("snippet" not in e for e in res["properties"]["evidence"])
    assert "setup.js:" in res["message"]["text"]


def test_lockfile_lines_v1_nested(demo_project):
    from tracii.inventory.lockfile import build_inventory
    from tracii.evidence.schema import ScanResult
    lock = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "requires": {"b": "^2"}, "dependencies": {"b": {"version": "2.0.0"}}},
        "b": {"version": "3.0.0"}}}, indent=2)
    pkg = json.dumps({"name": "x", "dependencies": {"a": "1.0.0", "b": "3.0.0"}})
    res = ScanResult(scan_id="s", source=ScanSource(kind="local", label="x"), inventory=build_inventory(pkg, lock),
                     findings=[], checks=[], created_at="2026-10-31T00:00:00+00:00")
    lines = sarif.lockfile_lines(lock, res)
    text = lock.splitlines()
    assert '"b"' in text[lines[("b", "2.0.0")] - 1] and '"2.0.0"' in text[lines[("b", "2.0.0")]]
    assert '"3.0.0"' in text[lines[("b", "3.0.0")]]
    # npm often writes small nested entries on one line: version on the key's own line
    lock = '{\n "lockfileVersion": 1,\n "dependencies": {\n  "a": {\n   "version": "1.0.0",\n' \
           '   "dependencies": {\n    "c": {"version": "9.9.9"}\n   }\n  }\n }\n}'
    res.inventory = build_inventory(json.dumps({"name": "x", "dependencies": {"a": "1"}}), lock)
    assert sarif.lockfile_lines(lock, res)[("c", "9.9.9")] == 7


# ---------- gate ----------

def test_gate_enforce_fails_on_high(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    g = gate.evaluate(scan, gate.GatePolicy(fail_on="high"))
    assert g.outcome == "fail" and g.exit_code == 1
    assert {f.package for f in g.blocking} == {"lodash", "minimist"}
    assert gate.evaluate(scan, gate.GatePolicy(fail_on="critical")).blocking[0].package == "minimist"
    assert gate.evaluate(scan, gate.GatePolicy(fail_on="none")).exit_code == 0


def test_gate_observe_mode_reports_but_passes(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    g = gate.evaluate(scan, gate.GatePolicy(mode="observe"))
    assert g.exit_code == 0 and g.would_fail and g.outcome == "fail"
    assert "observe mode" in gate.markdown_summary(scan, g)


def test_gate_failed_osv_is_incomplete_not_pass(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    scan.findings = []
    scan.checks = [c if c.name != "osv" else CheckRun(name="osv", status="failed", detail="timeout") for c in scan.checks]
    g = gate.evaluate(scan, gate.GatePolicy())
    assert g.outcome == "incomplete" and g.exit_code == 2 and g.failed_checks == ["osv"]
    allowed = gate.evaluate(scan, gate.GatePolicy(allow_incomplete=True))
    assert allowed.exit_code == 0
    md = gate.markdown_summary(scan, allowed)
    assert md.startswith("## ⚠️") and "incomplete scan allowed" in md and "did not run" in md


def test_gate_unknown_severity_and_dev_only(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    for f in scan.findings:
        f.severity = Severity.UNKNOWN
    g = gate.evaluate(scan, gate.GatePolicy())
    assert g.outcome == "pass" and len(g.unknown) == len(scan.findings)
    assert "unknown severity" in gate.markdown_summary(scan, g)
    assert gate.evaluate(scan, gate.GatePolicy(fail_on_unknown=True)).outcome == "fail"
    for f in scan.findings:
        f.severity = Severity.HIGH
        for p in f.paths:
            p.dev_only = True
    assert gate.evaluate(scan, gate.GatePolicy(include_dev=False)).outcome == "pass"
    assert "(dev only)" in gate.markdown_summary(scan, gate.evaluate(scan, gate.GatePolicy()))


def test_gate_markdown_escapes_package_text(demo_project, mock_http):
    _, scan = scan_demo(demo_project, mock_http)
    scan.findings[0].title = "x | <img src=x onerror=alert(1)>"
    scan.findings[0].severity = Severity.CRITICAL
    md = gate.markdown_summary(scan, gate.evaluate(scan, gate.GatePolicy()))
    assert "<img" not in md and "\\|" in md


# ---------- SBOM ----------

def test_purl_and_sri():
    assert sbom.purl("@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert sbom.purl("lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"
    h = sbom.sri_hashes("sha512-" + "A" * 86 + "== sha1-bogus!!")
    assert h == [{"alg": "SHA-512", "content": "00" * 64}]


def test_cyclonedx_components_graph_and_vulns(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    bom = sbom.to_cyclonedx(scan, rec.package_json)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["version"] == "1.0.0"
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)) == len({(p.name, p.version) for p in scan.inventory.packages})
    known = set(refs) | {"tracii:app"}
    assert all(d["ref"] in known and set(d["dependsOn"]) <= known for d in bom["dependencies"])
    root = next(d for d in bom["dependencies"] if d["ref"] == "tracii:app")
    assert "pkg:npm/lodash@4.17.20" in root["dependsOn"]
    express = next(d for d in bom["dependencies"] if d["ref"] == "pkg:npm/express@4.17.1")
    assert "pkg:npm/qs@6.7.0" in express["dependsOn"]
    lodash = next(c for c in bom["components"] if c["name"] == "lodash")
    assert lodash["hashes"][0]["alg"] == "SHA-512" and len(lodash["hashes"][0]["content"]) == 128
    assert {v["id"] for v in bom["vulnerabilities"]} == {"GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h"}
    assert "vulnerabilities" not in sbom.to_cyclonedx(scan, rec.package_json, include_vulnerabilities=False)


def test_cyclonedx_dev_scope_and_no_malware_in_vulns(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    for p in scan.inventory.packages:
        p.dev = p.name == "lodash"
    scan.findings += analyze_package(load_local_package(FIXTURES / "packages" / "fake-exfil"))
    bom = sbom.to_cyclonedx(scan, rec.package_json)
    lodash = next(c for c in bom["components"] if c["name"] == "lodash")
    assert lodash["scope"] == "excluded"
    assert {"name": "cdx:npm:package:development", "value": "true"} in lodash["properties"]
    assert next(c for c in bom["components"] if c["name"] == "express")["scope"] == "required"
    assert {v["id"] for v in bom["vulnerabilities"]} == {"GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h"}


# ---------- CLI ----------

def _patch_scan(monkeypatch, mock_http):
    real = cli.run_scan
    monkeypatch.setattr(cli, "run_scan", lambda rec, src, pkg, lock, deep_limit=None:
                        real(rec, src, pkg, lock, http=mock_http(), deep_limit=0))


def test_cli_scan_writes_outputs_and_exit_code(tmp_path, monkeypatch, mock_http, capsys):
    _patch_scan(monkeypatch, mock_http)
    out, step = tmp_path / "gh_out", tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    d = FIXTURES / "projects" / "vulnerable-demo"
    code = cli.main(["scan", "--dir", str(d), "--lockfile-uri", "package-lock.json",
                     "--sarif", str(tmp_path / "r.sarif"), "--sbom", str(tmp_path / "s.json"),
                     "--json", str(tmp_path / "r.json")])
    assert code == 1
    assert json.loads((tmp_path / "r.sarif").read_text())["runs"][0]["results"]
    assert json.loads((tmp_path / "s.json").read_text())["bomFormat"] == "CycloneDX"
    assert json.loads((tmp_path / "r.json").read_text())["gate"]["outcome"] == "fail"
    assert "outcome=fail" in out.read_text() and "FAIL" in step.read_text()
    assert cli.main(["scan", "--fixture", "vulnerable-demo", "--mode", "observe"]) == 0
    assert cli.main(["scan", "--fixture", "vulnerable-demo", "--fail-on", "none"]) == 0


def test_cli_bad_input_exits_2(tmp_path, capsys):
    (tmp_path / "package.json").write_text("{}")
    assert cli.main(["scan", "--dir", str(tmp_path)]) == 2
    assert "package-lock.json not found" in capsys.readouterr().err
    (tmp_path / "package-lock.json").write_text("{bad")
    assert cli.main(["sbom", "--dir", str(tmp_path), "-o", str(tmp_path / "x.json")]) == 2


def test_cli_sbom_is_offline(tmp_path, monkeypatch):
    import httpx

    def no_network(*a, **k):
        raise AssertionError("sbom must not touch the network")
    monkeypatch.setattr(httpx.Client, "send", no_network)
    target = tmp_path / "bom.json"
    assert cli.main(["sbom", "--fixture", "vulnerable-demo", "-o", str(target)]) == 0
    bom = json.loads(target.read_text())
    assert len(bom["components"]) > 10 and "vulnerabilities" not in bom


# ---------- API ----------

def test_api_export_endpoints(demo_project, mock_http):
    rec, _ = scan_demo(demo_project, mock_http)
    rec.status = "done"
    client = TestClient(api.app)
    r = client.get(f"/api/scans/{rec.scan_id}/sarif")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
    assert "attachment" in r.headers["content-disposition"] and r.json()["version"] == "2.1.0"
    assert r.text.startswith('{\n  "$schema"')
    r = client.get(f"/api/scans/{rec.scan_id}/sbom?vulnerabilities=false")
    assert r.json()["specVersion"] == "1.5" and "vulnerabilities" not in r.json()
    assert r.text.startswith('{\n  "bomFormat"') and r.text.endswith("}\n")
    g = client.get(f"/api/scans/{rec.scan_id}/gate?fail_on=critical").json()
    assert g["outcome"] == "fail" and len(g["blocking"]) == 1
    assert client.get("/api/scans/nope/sarif").status_code == 404
