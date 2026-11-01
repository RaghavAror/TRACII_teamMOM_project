import json

import httpx
import pytest
from fastapi.testclient import TestClient

from tracii import pipeline
from tracii.ai import meta_client, models
from tracii.ai.meta_client import MetaClient, ModelUnavailable
from tracii.api import main as api
from tracii.fix import remediation

REGISTRY_LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
}}).encode()


@pytest.mark.parametrize("spec", [
    "http://169.254.169.254/latest/meta-data", "git+ssh://git@github.com/a/b.git", "file:../../etc",
    "link:/etc", "github:owner/repo", "owner/repo", "https://evil.example/x.tgz",
])
def test_fix_simulation_refuses_non_registry_specs(spec):
    pkg = json.dumps({"name": "app", "dependencies": {"x": spec}})
    with pytest.raises(RuntimeError, match="registry"):
        remediation.check_resolvable(pkg, None)


def test_fix_simulation_refuses_nested_override_urls_and_workspaces():
    with pytest.raises(RuntimeError):
        remediation.check_resolvable(json.dumps({"overrides": {"a": {"b": "http://x"}}}), None)
    with pytest.raises(RuntimeError, match="workspace"):
        remediation.check_resolvable(json.dumps({"workspaces": ["../../"]}), None)


def test_fix_simulation_refuses_lockfile_outside_registry():
    lock = json.dumps({"packages": {"node_modules/x": {"version": "1.0.0", "resolved": "http://10.0.0.1/x.tgz"}}})
    with pytest.raises(RuntimeError, match="outside registry"):
        remediation.check_resolvable(json.dumps({"dependencies": {"x": "1.0.0"}}), lock.encode())


def test_fix_simulation_accepts_registry_specs(demo_project):
    pkg = {"dependencies": {"a": "^1.2.3", "b": "~2.0.0 || >=3", "c": "latest", "d": "npm:@scope/real@^1",
                            "e": "1.x", "f": "*"}, "overrides": {"g": "$a", "h": {"i": "2.0.0"}}}
    remediation.check_resolvable(json.dumps(pkg), REGISTRY_LOCK)
    remediation.check_resolvable(demo_project[0].decode(), demo_project[1])   # the demo project must still simulate


def test_store_drops_oldest_finished_scans(monkeypatch):
    monkeypatch.setattr(pipeline, "MAX_STORED_SCANS", 3)
    store = pipeline.Store()
    running = store.new()
    done = []
    for _ in range(4):
        r = store.new()
        r.status = "done"
        done.append(r)
    store.new()
    assert store.get(running.scan_id) is not None          # running scans are never evicted
    assert store.get(done[0].scan_id) is None and store.get(done[-1].scan_id) is not None


def test_post_rate_limit(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "2")
    api._HITS.clear()
    c = TestClient(api.app)
    codes = [c.post("/api/scan/fixture", json={"name": "nope"}).status_code for _ in range(3)]
    assert codes == [404, 404, 429]
    assert c.get("/api/health").status_code == 200          # reads are not limited
    api._HITS.clear()


def test_failed_call_shows_as_failed_then_verified_after_success(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    meta_client.FAILED.clear()
    model = models.ROLES[0].model_id
    bad = MetaClient("k", retries=0, client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(401, text="bad key"))))
    with pytest.raises(ModelUnavailable):
        bad.chat_json(model, "s", "u", models.PING_SCHEMA, "ping")
    row = next(r for r in models.status() if r["role"] == "investigator")
    assert row["status"] == "failed" and "401" in row["error"]
    good = MetaClient("k", retries=0, client=httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": '{"ok": true}'}}]}))))
    good.chat_json(model, "s", "u", models.PING_SCHEMA, "ping")
    assert next(r for r in models.status() if r["role"] == "investigator")["status"] == "verified"
    meta_client.FAILED.clear()


def test_image_role_explains_its_flag(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    image = next(r for r in models.status() if r["role"] == "image")
    assert image["status"] == "not_configured" and "ENABLE_REPORT_IMAGES" in image["note"]


def test_model_check_without_credentials_makes_no_calls(monkeypatch):
    monkeypatch.setattr(api, "_LAST_CHECK", {"at": 0.0, "results": []})
    body = TestClient(api.app).post("/api/models/check").json()
    assert body["results"] == [] and all(r["status"] != "verified" for r in body["status"])
