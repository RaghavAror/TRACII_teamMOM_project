"""The PDF report must be built from the stored scan, keep finding types apart and never invent content."""

import pytest
from fastapi.testclient import TestClient
from reportlab import rl_config

from tests.conftest import FIXTURES
from tracii import gate
from tracii.api import main as api
from tracii.evidence.schema import Category, CheckRun, Evidence, Finding, ScanSource, Severity
from tracii.export.pdf_report import build_pdf
from tracii.pipeline import STORE, run_scan


@pytest.fixture(autouse=True)
def plain_streams(monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)   # searchable text in the test PDFs


def _scan(mock_http, name="vulnerable-demo"):
    d = FIXTURES / "projects" / name
    rec = STORE.new()
    run_scan(rec, ScanSource(kind="fixture", label=name), (d / "package.json").read_bytes(),
             (d / "package-lock.json").read_bytes(), http=mock_http(), deep_limit=0)
    return rec


def test_pdf_endpoint_returns_this_scans_report(mock_http):
    rec = _scan(mock_http)
    r = TestClient(api.app).get(f"/api/scans/{rec.scan_id}/report.pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF") and f"tracii-report-{rec.scan_id}.pdf".encode() in r.headers["content-disposition"].encode()
    body = r.content
    assert rec.scan_id.encode() in body and b"GHSA-xvch-5gv4-984h" in body and b"minimist@1.2.5" in body
    assert b"CI gate: FAIL" in body
    # no AI call was made for this scan: the report must say so instead of inventing AI content
    assert b"No AI investigation was run for this scan" in body
    assert TestClient(api.app).get("/api/scans/nope/report.pdf").status_code == 404


def test_pdf_threshold_follows_request(mock_http):
    rec = _scan(mock_http)
    c = TestClient(api.app)
    assert b"CI gate: PASS" in c.get(f"/api/scans/{rec.scan_id}/report.pdf?fail_on=none").content
    assert b"fail on critical" in c.get(f"/api/scans/{rec.scan_id}/report.pdf?fail_on=critical").content


def test_pdf_keeps_types_apart_marks_skipped_checks_and_only_real_ai(mock_http):
    rec = _scan(mock_http)
    res = rec.result
    mal = Finding(id="malfinding01", category=Category.MALICIOUS_INDICATOR, source="osv-api", rule_or_advisory="MAL-2023-462",
                  title="Malicious code in evil", package="evil", version="1.0.0", severity=Severity.CRITICAL,
                  evidence=[Evidence(id="malfinding01-adv", kind="advisory", summary="evil is listed as malicious <script>")])
    sus = Finding(id="susfinding01", category=Category.MALICIOUS_INDICATOR, source="tracii-static", rule_or_advisory="TRACII-CHAIN-EXFIL",
                  title="Data theft chain", package="odd", version="2.0.0", severity=Severity.HIGH)
    res.findings += [mal, sus]
    res.checks.append(CheckRun(name="guarddog", status="not_configured", detail="Install guarddog"))
    vuln = next(f for f in res.findings if f.category == Category.VULNERABILITY)
    notes = {vuln.id: {"explain": {"model": "muse-spark-1.3", "assessment": "known_vulnerability_applies", "confidence": "high",
                                   "scanner_category": "known_vulnerability", "scanner_severity": vuln.severity.value,
                                   "observed": "observed text", "claims": [{"text": "grounded claim", "evidence_ids": ["e1"]}],
                                   "next_action": "upgrade"}}}
    pdf = build_pdf(res, gate.evaluate(res, gate.GatePolicy()), notes)
    # PDF string syntax escapes parentheses, so match the text around them
    assert b"Known malicious package \\(OSV MAL- record\\)" in pdf
    assert b"not confirmed" in pdf and b"Suspicious behaviour" in pdf
    assert b"Known vulnerability \\(advisory\\)" in pdf
    assert b"CONFIGURED" in pdf and b"SKIPPED" in pdf         # not-run checks are never shown as passed
    assert b"muse-spark-1.3" in pdf and b"grounded claim" in pdf
    # untrusted package text is shown literally (escaped for the markup parser, not dropped or interpreted)
    assert b"malicious <" in pdf and b"script" in pdf and b"&lt;" not in pdf


def test_explain_result_is_recorded_only_when_ai_succeeded(mock_http):
    rec = _scan(mock_http)
    rec.status = "done"
    f = rec.result.findings[0]
    r = TestClient(api.app).post(f"/api/scans/{rec.scan_id}/findings/{f.id}/explain", json={})
    assert r.status_code == 200 and r.json()["ai_status"] == "unavailable"   # no key in tests
    assert rec.ai_notes == {}
