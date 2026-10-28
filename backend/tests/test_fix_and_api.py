import json
import time

from fastapi.testclient import TestClient

from tests.conftest import FIXTURES, fixture_tarball
from tracii.api import main as api
from tracii.evidence.schema import RemediationStatus, ScanSource
from tracii.fix import remediation
from tracii.pipeline import STORE, run_scan


def scan_demo(demo_project, mock_http, packages=None, deep_limit=0):
    rec = STORE.new()
    return rec, run_scan(rec, ScanSource(kind="fixture", label="t"), *demo_project,
                         http=mock_http(packages), deep_limit=deep_limit)


def test_fix_direct_dependency_bump(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    lodash = next(f for f in scan.findings if f.package == "lodash")
    p = remediation.propose_fix(lodash, scan.inventory, rec.package_json)
    assert p.kind == "bump_direct" and p.to_version == "4.17.21"
    assert json.loads(p.new_package_json)["dependencies"]["lodash"] == "4.17.21"
    assert '-    "lodash": "4.17.20"' in p.diff and '+    "lodash": "4.17.21"' in p.diff


def test_fix_transitive_uses_override(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    minimist = next(f for f in scan.findings if f.package == "minimist")
    # minimist is also declared as a devDependency in the demo -> direct bump
    assert remediation.propose_fix(minimist, scan.inventory, rec.package_json).kind == "bump_direct"
    pkg = json.loads(rec.package_json)
    del pkg["devDependencies"]["minimist"]
    p = remediation.propose_fix(minimist, scan.inventory, json.dumps(pkg))
    assert p.kind == "override_transitive" and json.loads(p.new_package_json)["overrides"] == {"minimist": "1.2.6"}
    assert "mkdirp" in p.reason and any("overrides" in c for c in p.caveats)


def test_malicious_indicator_never_gets_auto_fix(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    from tracii.detect.static_rules import analyze_package
    from tracii.intake.npm_registry import load_local_package
    f = analyze_package(load_local_package(FIXTURES / "packages" / "fake-exfil"))[0]
    p = remediation.propose_fix(f, scan.inventory, rec.package_json)
    assert p.kind == "manual_review" and p.new_package_json is None


def test_pick_fixed_version_prefers_same_major():
    assert remediation.pick_fixed_version("1.2.5", ["0.2.4", "1.2.6", "2.0.0"]) == "1.2.6"
    assert remediation.pick_fixed_version("1.2.6", ["1.2.6"]) is None


def test_comparison_and_status():
    from tracii.detect.osv import vuln_to_finding
    old = vuln_to_finding({"id": "GHSA-a"}, "p", "1.0.0", "osv-api")
    other = vuln_to_finding({"id": "GHSA-b"}, "q", "1.0.0", "osv-api")
    new = vuln_to_finding({"id": "GHSA-c"}, "p", "2.0.0", "osv-api")
    cmp = remediation.compare([old, other], [other, new])
    assert [f["rule_or_advisory"] for f in cmp["fixed"]] == ["GHSA-a"]
    assert [f["rule_or_advisory"] for f in cmp["remaining"]] == ["GHSA-b"]
    assert [f["rule_or_advisory"] for f in cmp["new"]] == ["GHSA-c"]
    prop = remediation.FixProposal(finding_id=old.id, kind="bump_direct", package="p", from_version="1.0.0",
                                   to_version="2.0.0", reason="")
    assert remediation.target_status(prop, cmp) == RemediationStatus.VERIFIED_FIXED
    assert remediation.target_status(prop, None) == RemediationStatus.UNVERIFIED


def test_deep_scan_attaches_malware_findings_and_paths(demo_project, mock_http):
    # serve the inert fixture under the name/version of a real demo dependency
    blob = fixture_tarball(FIXTURES / "packages" / "fake-exfil")
    _, scan = scan_demo(demo_project, mock_http, packages={("mkdirp", "0.5.5"): blob}, deep_limit=60)
    mal = [f for f in scan.findings if f.category.value == "malicious_indicator" and f.package == "mkdirp"]
    assert any(f.rule_or_advisory == "TRACII-CHAIN-EXFIL" for f in mal)
    assert mal[0].paths[0].nodes == ["<app>", "mkdirp@0.5.5"]
    static = next(c for c in scan.checks if c.name == "tracii-static")
    assert "fetch errors" in static.detail   # other packages 404 in the mock: reported, not hidden
    assert next(c for c in scan.checks if c.name == "guarddog").status == "not_configured"


# ---- API ----

client = TestClient(api.app)


def test_upload_malformed_json_is_400():
    r = client.post("/api/scan/upload", files={"package_json": ("package.json", b"{bad"),
                                               "package_lock": ("package-lock.json", b"{}")})
    assert r.status_code == 400 and "not valid JSON" in r.json()["detail"]


def test_upload_too_large_is_413(monkeypatch):
    monkeypatch.setattr(api, "MAX_UPLOAD", 10)
    r = client.post("/api/scan/upload", files={"package_json": ("p", b"{" + b" " * 20 + b"}"),
                                               "package_lock": ("l", b"{}")})
    assert r.status_code == 413


def test_github_url_validation():
    r = client.post("/api/scan/github", json={"url": "https://evil.example.com/a/b"})
    assert r.status_code == 400
    r = client.post("/api/scan/github", json={"url": "https://github.com/a/b", "subdir": "../../etc"})
    assert r.status_code in (400, 502)


def test_rescan_unverified_when_resolver_unavailable(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    lodash = next(f for f in scan.findings if f.package == "lodash")
    r = client.post(f"/api/scans/{rec.scan_id}/findings/{lodash.id}/rescan")
    body = r.json()
    assert body["status"] == "unverified" and body["comparison"] is None
    assert "could not run" in body["detail"]


def test_explain_endpoint_works_without_model(demo_project, mock_http):
    rec, scan = scan_demo(demo_project, mock_http)
    r = client.post(f"/api/scans/{rec.scan_id}/findings/{scan.findings[0].id}/explain", json={})
    assert r.status_code == 200 and r.json()["ai_status"] == "unavailable"


def test_report_image_disabled_by_default(demo_project, mock_http):
    rec, _ = scan_demo(demo_project, mock_http)
    assert client.post(f"/api/scans/{rec.scan_id}/report/image").status_code == 404


def test_segment_rejects_non_image():
    r = client.post("/api/evidence/segment", files={"image": ("x.png", b"GIF89a")}, data={"prompt": "terminal"})
    assert r.status_code == 400


def test_models_status_endpoint():
    rows = client.get("/api/models/status").json()
    assert {r["model"] for r in rows} >= {"muse-spark-1.3", "muse-wonder-1.0", "muse-image-1.0",
                                         "muse-voice-transcribe-1.0", "sam-3.1"}


def test_fix_target_covers_all_advisories_on_package():
    from tracii.detect.osv import vuln_to_finding
    from tracii.evidence.schema import Inventory

    def adv(i, fixed):
        return vuln_to_finding({"id": i, "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}]},
                               "lodash", "4.17.20", "osv-api")
    a, b, c = adv("GHSA-a", "4.17.21"), adv("GHSA-b", "4.18.0"), adv("GHSA-c", "4.17.23")
    inv = Inventory(project_name="x", lockfile_version=3, packages=[], declared={"lodash": "4.17.20"}, declared_dev={})
    p = remediation.propose_fix(a, inv, '{"dependencies": {"lodash": "4.17.20"}}', [a, b, c])
    assert p.to_version == "4.18.0" and any("2 other advisories" in x for x in p.caveats)


def test_compare_separates_coverage_changes_from_regressions():
    from tracii.detect.static_rules import analyze_package
    from tracii.intake.npm_registry import load_local_package
    mal = analyze_package(load_local_package(FIXTURES / "packages" / "fake-exfil"))
    cmp = remediation.compare([], mal, deep_before=set())
    assert cmp["new"] == [] and len(cmp["newly_covered"]) == len(mal)
    assert len(remediation.compare([], mal, deep_before={"fake-exfil"})["new"]) == len(mal)
