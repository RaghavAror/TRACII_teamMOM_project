"""Numbers shown in the UI must come from real data: the current scan, or the documented benchmark."""

import json
import time

import httpx
from fastapi.testclient import TestClient

from tests.conftest import FIXTURES, ROOT
from tracii import cli, gate
from tracii.ai import investigator
from tracii.ai.meta_client import OpenAICompatClient
from tracii.api import main as api
from tracii.evidence.schema import ScanSource
from tracii.export.sbom import to_cyclonedx
from tracii.pipeline import STORE, run_scan
from tests.test_ai import chain_finding


def _scan(name, mock_http):
    d = FIXTURES / "projects" / name
    rec = STORE.new()
    run_scan(rec, ScanSource(kind="fixture", label=name), (d / "package.json").read_bytes(),
             (d / "package-lock.json").read_bytes(), http=mock_http(), deep_limit=0)
    return rec


def test_benchmark_matches_readme_table():
    bench = TestClient(api.app).get("/api/benchmark").json()
    readme = (ROOT / "README.md").read_text()
    assert bench["kind"] == "fixed_benchmark" and "not computed from your scan" in bench["disclaimer"].lower()
    for s in bench["sets"]:
        m, b = s["malware"], s["benign"]
        for k in (m["rules"], m["rules_plus_osv"]):
            assert f"{k}/{m['n']}" in readme, (s["name"], k)
        assert f"{b['false_alarms']}/{b['n']}" in readme, s["name"]


def test_clean_project_gets_no_fabricated_findings_and_passes(mock_http):
    rec = _scan("clean-demo", mock_http)
    assert rec.status == "done"
    assert not [f for f in rec.result.findings if f.severity.value not in ("info",)]
    g = TestClient(api.app).get(f"/api/scans/{rec.scan_id}/gate").json()
    assert g["outcome"] == "pass" and g["exit_code"] == 0 and g["blocking"] == []


def test_gate_api_matches_cli_exit_code_for_every_threshold(mock_http, monkeypatch):
    rec = _scan("vulnerable-demo", mock_http)
    real = cli.run_scan
    monkeypatch.setattr(cli, "run_scan", lambda r, src, pkg, lock, deep_limit=None:
                        real(r, src, pkg, lock, http=mock_http(), deep_limit=0))
    c = TestClient(api.app)
    for t in gate.THRESHOLDS:
        g = c.get(f"/api/scans/{rec.scan_id}/gate?fail_on={t}").json()
        expected = gate.evaluate(rec.result, gate.GatePolicy(fail_on=t))
        assert g["exit_code"] == expected.exit_code == cli.main(["scan", "--fixture", "vulnerable-demo", "--fail-on", t])
        gated = [f for f in rec.result.findings if f.category.value in g["policy"]["categories"]]
        assert len(g["blocking"]) + g["non_blocking"] == len(gated)
    assert c.get(f"/api/scans/{rec.scan_id}/gate?mode=observe").json()["exit_code"] == 0


def test_licenses_come_from_lockfile_and_reach_the_sbom(mock_http):
    rec = _scan("vulnerable-demo", mock_http)
    lock = json.loads((FIXTURES / "projects" / "vulnerable-demo" / "package-lock.json").read_text())["packages"]
    for p in rec.result.inventory.packages:
        assert p.license == lock[p.path].get("license")
    comps = {c["name"]: c for c in to_cyclonedx(rec.result, rec.package_json)["components"]}
    assert comps["lodash"]["licenses"] == [{"license": {"name": "MIT"}}]


def test_slow_independent_assessor_times_out_without_blocking(monkeypatch):
    f, slices = chain_finding()

    def slow(request):
        time.sleep(3)
        return httpx.Response(500)
    fake = OpenAICompatClient("http://slow.local/v1", "none", retries=0, client=httpx.Client(transport=httpx.MockTransport(slow)))
    monkeypatch.setattr(investigator, "open_weight_clients", lambda: {"glimmer": (fake, "slow-model")})
    t = time.monotonic()
    out = investigator.independent_assessments(f, slices, {"assessment": "x"}, timeout=0.5)
    assert time.monotonic() - t < 2
    assert out[0]["status"] == "timeout" and out[0]["model"] == "slow-model"
