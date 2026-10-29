import json

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.conftest import FIXTURES
from tracii import replay
from tracii.ai import agents, enrich
from tracii.ai.meta_client import MetaClient
from tracii.api import main as api
from tracii.detect.osv import vuln_to_finding
from tracii.detect.static_rules import analyze_package
from tracii.evidence.schema import ScanSource
from tracii.impact.paths import APP, DependencyGraph
from tracii.intake.npm_registry import load_local_package
from tracii.inventory.lockfile import build_inventory
from tracii.pipeline import STORE, run_scan

LODASH_ADV = {"id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash", "aliases": ["CVE-2021-23337"],
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
              "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}


def vuln_finding():
    return vuln_to_finding(LODASH_ADV, "lodash", "4.17.20", "osv-api")


def intel_http(in_kev=False, scorecard=6.5):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "api.first.org":
            return httpx.Response(200, json={"data": [{"cve": "CVE-2021-23337", "epss": "0.21", "percentile": "0.97",
                                                       "date": "2026-10-29"}]})
        if req.url.host == "www.cisa.gov":
            vulns = [{"cveID": "CVE-2021-23337", "dateAdded": "2026-01-01"}] if in_kev else []
            return httpx.Response(200, json={"catalogVersion": "test", "vulnerabilities": vulns})
        if req.url.host == "registry.npmjs.org":
            return httpx.Response(200, json={"name": "lodash", "version": "4.17.20", "dist": {},
                                             "maintainers": [{"name": "a"}, {"name": "b"}],
                                             "repository": {"url": "git+https://github.com/lodash/lodash.git"}})
        if req.url.host == "api.securityscorecards.dev":
            return httpx.Response(200, json={"score": scorecard, "date": "2026-10-27",
                                             "checks": [{"name": "Signed-Releases", "score": 0}]})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def scripted_model(answers: dict, seen: list | None = None):
    """Answers keyed by response_format schema name, e.g. 'tracii_vuln_triage'."""
    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        name = body["response_format"]["json_schema"]["name"]
        if seen is not None:
            seen.append(body)
        payload = answers[name](body) if callable(answers[name]) else answers[name]
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(payload)}}]})
    return MetaClient(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)), retries=0)


@pytest.fixture(autouse=True)
def fresh_kev(monkeypatch):
    monkeypatch.setattr(enrich, "_kev_cache", {"at": 0.0, "by_cve": {}, "version": ""})


# ---------- SSVC ----------

def test_ssvc_uses_official_cisa_table():
    assert len(agents.SSVC_TABLE) == 36
    assert agents.ssvc_outcome("active", "yes", "total", "high")["decision"] == "act"
    assert agents.ssvc_outcome("none", "no", "partial", "low")["decision"] == "track"
    # rows that differ from a naive reading of the tree, checked against CERTCC/SSVC
    assert agents.ssvc_outcome("public poc", "yes", "total", "medium")["decision"] == "track*"
    assert agents.ssvc_outcome("active", "yes", "total", "medium")["decision"] == "act"


def test_ssvc_open_decision_points_become_a_range():
    out = agents.ssvc_outcome("active", None, None, "medium")
    assert not out["settled"] and out["range"] == ["track", "attend", "act"] and out["decision"] == "act"


# ---------- agents ----------

def test_uncited_decision_point_is_left_open_and_kev_forces_active():
    f = vuln_finding()
    known = {f"{f.id}-adv", f"{f.id}-x-kev-CVE-2021-23337"}
    raw = {"summary": "s", "claims": [], "unknowns": [], "method": {
        "exploitation": {"value": "none", "evidence_ids": []},
        "automatable": {"value": "no", "evidence_ids": [f"{f.id}-adv"]},
        "technical_impact": {"value": "total", "evidence_ids": ["invented-id"]}}}
    out = agents.validate_agent(agents.AGENTS[0], raw, known, "high", {"in_kev": True})
    assert out["method"]["exploitation"]["value"] == "active"          # KEV is authoritative
    assert out["method"]["technical_impact"]["value"] is None          # cited an unknown ID
    assert out["ssvc"]["range"] == ["attend", "act"]
    assert any("technical_impact" in u for u in out["unknowns"])


def test_attack_mapping_drops_invented_techniques_and_uncited_items():
    pkg = load_local_package(FIXTURES / "packages" / "fake-exfil")
    f = next(x for x in analyze_package(pkg) if x.rule_or_advisory == "TRACII-CHAIN-EXFIL")
    ev = f.evidence[0].id
    raw = {"summary": "s", "claims": [], "unknowns": [], "method": {"techniques": [
        {"technique_id": "T1552", "evidence_ids": [ev], "rationale": "reads env"},
        {"technique_id": "T9999", "evidence_ids": [ev], "rationale": "made up"},
        {"technique_id": "T1041", "evidence_ids": [], "rationale": "no citation"}]}}
    out = agents.validate_agent(agents.AGENTS[1], raw, {e.id for e in f.evidence}, "medium", {})
    assert [t["technique_id"] for t in out["method"]["techniques"]] == ["T1552"]
    assert out["method"]["techniques"][0]["name"] == "Unsecured Credentials"
    assert len(out["discarded_claims"]) == 1


def test_investigate_vulnerability_end_to_end_with_mocked_models():
    f = vuln_finding()
    adv, kev = f"{f.id}-adv", f"{f.id}-x-kev"
    dp = {"value": "no", "evidence_ids": [adv]}
    answers = {
        "tracii_vuln_triage": {"summary": "v", "unknowns": [],
                               "claims": [{"text": "EPSS is high", "evidence_ids": [f"{f.id}-x-epss-CVE-2021-23337"]},
                                          {"text": "uncited", "evidence_ids": []}],
                               "method": {"exploitation": {"value": "none", "evidence_ids": [kev]}, "automatable": dp,
                                          "technical_impact": {"value": "total", "evidence_ids": [adv]}}},
        "tracii_integrity": {"summary": "i", "unknowns": [], "claims": [], "method": {"controls": [
            {"control": "provenance", "status": "missing", "evidence_ids": [f"{f.id}-x-prov"]}]}},
        "tracii_threat_model": {"summary": "t", "unknowns": [], "claims": [], "method": {"threats": []}},
        "tracii_judge": {"priority": "track", "verdict": "ok", "agreements": [], "conflicts": [], "next_steps": [],
                         "unknowns": [], "claims": [{"text": "c", "evidence_ids": [adv]}]},
    }
    seen = []
    out = agents.investigate(f, [], scripted_model(answers, seen), http=intel_http(), mission_impact="medium")
    by = {a["agent"]: a for a in out["agents"]}
    assert set(by) == {"vuln_triage", "integrity", "threat_model"}
    assert [s["agent"] for s in out["skipped_agents"]] == ["attack_mapping"]
    assert by["vuln_triage"]["ssvc"] == agents.ssvc_outcome("none", "no", "total", "medium")
    assert len(by["vuln_triage"]["claims"]) == 1 and len(by["vuln_triage"]["discarded_claims"]) == 1
    assert by["integrity"]["method"]["controls"][0]["status"] == "missing"
    assert out["judge"]["ai_status"] == "ok" and out["judge"]["priority"] == "track"
    ids = {e["id"] for e in out["enrichment"]["evidence"]}
    assert {f"{f.id}-x-epss-CVE-2021-23337", kev, f"{f.id}-x-prov", f"{f.id}-x-sc"} <= ids
    # enrichment facts reach the agents as citable evidence; package text stays fenced
    prompt = next(b for b in seen if b["response_format"]["json_schema"]["name"] == "tracii_vuln_triage")
    user = prompt["messages"][1]["content"]
    assert f"{f.id}-x-epss-CVE-2021-23337" in user and "<untrusted_package_data>" in user
    assert out["independent_review"] == []   # no open-weight endpoint configured in tests


def test_investigate_without_model_is_deterministic_and_labelled():
    f = vuln_finding()
    out = agents.investigate(f, [], MetaClient(api_key=""), http=intel_http(in_kev=True), mission_impact="high")
    assert all(a["ai_status"] == "unavailable" for a in out["agents"])
    triage = next(a for a in out["agents"] if a["agent"] == "vuln_triage")
    assert triage["method"]["exploitation"]["value"] == "active" and triage["ssvc"]["range"] == ["attend", "act"]
    assert out["judge"]["ai_status"] == "unavailable" and out["judge"]["priority"] == "insufficient_evidence"


def test_enrichment_failure_is_a_limitation_not_a_guess():
    f = vuln_finding()
    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    out = enrich.threat_intel(f, down)
    assert out.evidence == [] and len(out.limitations) == 2 and out.facts["in_kev"] is False


def test_open_weight_reviewer_runs_beside_the_judge(monkeypatch):
    monkeypatch.setenv("SPARK_OPEN_BASE_URL", "https://spark-open.test/v1")
    monkeypatch.setenv("SPARK_OPEN_MODEL", "meta-models/muse-spark-open-1026")
    monkeypatch.setenv("META_API_KEY", "test-key")
    pkg = load_local_package(FIXTURES / "packages" / "fake-exfil")
    f = next(x for x in analyze_package(pkg) if x.rule_or_advisory == "TRACII-CHAIN-EXFIL")

    def handler(req):
        body = json.loads(req.content)
        if req.url.host == "spark-open.test":
            pay = {"priority": "attend", "verdict": "v", "claims": [], "agreements": [], "conflicts": [],
                   "next_steps": [], "unknowns": []}
        elif req.url.host == "registry.npmjs.org":
            return httpx.Response(404)
        else:
            name = body["response_format"]["json_schema"]["name"]
            pay = ({"priority": "act_now", "verdict": "v", "claims": [], "agreements": [], "conflicts": [],
                    "next_steps": [], "unknowns": []} if name == "tracii_judge" else
                   {"summary": "s", "claims": [], "unknowns": [],
                    "method": {"techniques": []} if name == "tracii_attack_mapping" else
                    {"controls": []} if name == "tracii_integrity" else {"threats": []}})
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(pay)}}]})

    from tracii.ai import meta_client, models
    real = meta_client.OpenAICompatClient.__init__

    def patched(self, base_url, api_key, **kw):
        real(self, base_url, api_key, client=httpx.Client(transport=httpx.MockTransport(handler)), retries=0)
    monkeypatch.setattr(meta_client.OpenAICompatClient, "__init__", patched)
    out = agents.investigate(f, [], models.meta_client(), http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert out["judge"]["priority"] == "act_now"
    assert out["independent_review"][0]["priority"] == "attend"
    assert out["independent_review"][0]["agrees_with_judge"] is False


# ---------- graph + replays ----------

def lock_project(deps: dict[str, dict], direct: dict[str, str], dev: dict[str, str] | None = None):
    """deps: name -> {"version": v, "dependencies": {...}} (all hoisted)."""
    pkgs = {"": {"name": "app", "version": "1.0.0", "dependencies": direct, "devDependencies": dev or {}}}
    for name, d in deps.items():
        pkgs[f"node_modules/{name}"] = {"version": d["version"], "dependencies": d.get("dependencies", {}),
                                        **({"dev": True} if d.get("dev") else {})}
    manifest = {"name": "app", "version": "1.0.0", "dependencies": direct, "devDependencies": dev or {}}
    return build_inventory(json.dumps(manifest), json.dumps({"name": "app", "lockfileVersion": 3, "packages": pkgs}))


def test_graph_overlay_and_dependent_waves():
    inv = lock_project({"web": {"version": "1.0.0", "dependencies": {"colors": "^1.4.0"}},
                        "colors": {"version": "1.4.1"},
                        "jest": {"version": "29.0.0", "dev": True}},
                       {"web": "^1.0.0"}, {"jest": "^29.0.0"})
    f = vuln_to_finding({"id": "GHSA-5rqg-jm4f-cqx7", "summary": "loop"}, "colors", "1.4.1", "osv-api")
    g = DependencyGraph(inv)
    data = g.graph_json([f])
    nodes = {n["id"]: n for n in data["nodes"]}
    assert nodes[APP]["app"] and {"source": APP, "target": "node_modules/web"} in data["edges"]
    assert nodes["node_modules/colors"]["findings"]["known_vulnerability"][0]["id"] == f.id
    assert nodes["node_modules/colors"]["dependents"] == 1
    assert nodes["node_modules/jest"]["dev_only"] and not nodes["node_modules/colors"]["dev_only"]
    assert g.dependent_waves("node_modules/colors") == [["node_modules/web"], [APP]]


def test_replay_in_project_flags_installed_malicious_version():
    inv = lock_project({"web": {"version": "1.0.0", "dependencies": {"colors": "^1.4.0"}},
                        "colors": {"version": "1.4.1"}}, {"web": "^1.0.0"})
    out = replay.replay(replay.get("colors-2022"), inv)
    t = out["targets"][0]
    assert out["mode"] == "in_project" and t["installed_is_malicious"] and t["affected_direct"] == ["web"]
    assert t["reaches_app"] and "malicious version" in out["note"] and "infinite loop" in out["note"]


def test_replay_simulates_on_most_depended_package_when_absent():
    inv = lock_project({"a": {"version": "1.0.0", "dependencies": {"core": "1"}},
                        "b": {"version": "1.0.0", "dependencies": {"core": "1"}},
                        "core": {"version": "1.0.0"}}, {"a": "1", "b": "1"})
    out = replay.replay(replay.get("event-stream-2018"), inv)
    assert out["mode"] == "simulated" and out["note"].startswith("SIMULATION")
    assert out["targets"][0]["label"] == "core@1.0.0" and out["targets"][0]["affected_direct"] == ["a", "b"]
    assert out["injected"] == {"package": "flatmap-stream", "version": "0.1.1"}


def test_replay_scenarios_are_sourced():
    for s in replay.SCENARIOS:
        assert s["advisories"] and s["detection"] and s["target"]["if_installed"]
        for step in s["steps"]:
            assert step["sources"] and all(u.startswith("https://") for u in step["sources"])
            assert set(step["techniques"]) <= set(agents.ATTACK_TECHNIQUES)


# ---------- API ----------

client = TestClient(api.app)


def test_agents_and_replay_endpoints(demo_project, mock_http, monkeypatch):
    monkeypatch.setattr(enrich, "provenance", lambda f, http: enrich.Enrichment())
    monkeypatch.setattr(enrich, "threat_intel", lambda f, http: enrich.Enrichment())
    rec = STORE.new()
    scan = run_scan(rec, ScanSource(kind="fixture", label="t"), *demo_project, http=mock_http(), deep_limit=0)
    fid = scan.findings[0].id
    r = client.post(f"/api/scans/{rec.scan_id}/findings/{fid}/agents", json={"mission_impact": "high"})
    assert r.status_code == 200 and r.json()["mission_impact_assumed"] == "high"
    assert client.post(f"/api/scans/{rec.scan_id}/findings/{fid}/agents", json={"mission_impact": "x"}).status_code == 422
    assert [s["id"] for s in client.get("/api/replays").json()] == [s["id"] for s in replay.SCENARIOS]
    r = client.post(f"/api/scans/{rec.scan_id}/replays/ua-parser-js-2021")
    assert r.status_code == 200 and r.json()["mode"] in ("in_project", "simulated")
    assert client.post(f"/api/scans/{rec.scan_id}/replays/nope").status_code == 404
    g = client.get(f"/api/scans/{rec.scan_id}/graph").json()
    assert any(n["findings"] for n in g["nodes"] if not n.get("app"))


def test_deferred_reviews_do_not_block_the_judge(monkeypatch):
    import threading
    import time as _time
    monkeypatch.setenv("META_API_KEY", "test-key")
    monkeypatch.setenv("GLIMMER_BASE_URL", "https://glimmer.test/v1")
    monkeypatch.setenv("GLIMMER_MODEL", "meta/muse-glimmer-30b")
    release = threading.Event()
    judge = {"priority": "track", "verdict": "v", "claims": [], "agreements": [], "conflicts": [],
             "next_steps": [], "unknowns": []}

    def handler(req):
        if req.url.host == "glimmer.test":
            release.wait(5)   # a slow free tier: answers only after the judge has returned
            pay = {**judge, "priority": "track"}
        elif req.url.host == "registry.npmjs.org":
            return httpx.Response(404)
        else:
            name = json.loads(req.content)["response_format"]["json_schema"]["name"]
            pay = judge if name == "tracii_judge" else {"summary": "s", "claims": [], "unknowns": [], "method": (
                {"techniques": []} if name == "tracii_attack_mapping" else
                {"controls": []} if name == "tracii_integrity" else {"threats": []})}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(pay)}}]})

    from tracii.ai import meta_client, models
    real = meta_client.OpenAICompatClient.__init__
    monkeypatch.setattr(meta_client.OpenAICompatClient, "__init__", lambda self, base_url, api_key, **kw: real(
        self, base_url, api_key, client=httpx.Client(transport=httpx.MockTransport(handler)), retries=0))
    pkg = load_local_package(FIXTURES / "packages" / "fake-exfil")
    f = next(x for x in analyze_package(pkg) if x.rule_or_advisory == "TRACII-CHAIN-EXFIL")
    out = agents.investigate(f, [], models.meta_client(), defer_reviews=True,
                             http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert out["judge"]["ai_status"] == "ok" and out["review_id"]
    assert [r["status"] for r in out["independent_review"]] == ["pending"]
    release.set()
    for _ in range(50):
        s = agents.review_status(out["review_id"])
        if s["done"]:
            break
        _time.sleep(0.05)
    assert s["done"] and s["reviews"][0]["priority"] == "track" and s["reviews"][0]["agrees_with_judge"] is True
    r = client.get(f"/api/reviews/{out['review_id']}")
    assert r.status_code == 200 and r.json()["done"]
    assert client.get("/api/reviews/nope").status_code == 404
