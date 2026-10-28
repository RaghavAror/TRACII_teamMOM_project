import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


def make_tarball(files: dict[str, bytes], extra: list[tarfile.TarInfo] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extra or []:
            tar.addfile(info)
    return buf.getvalue()


def integrity(blob: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode()


def fixture_tarball(pkg_dir: Path) -> bytes:
    return make_tarball({f"package/{p.relative_to(pkg_dir).as_posix()}": p.read_bytes()
                         for p in pkg_dir.rglob("*") if p.is_file()})


@pytest.fixture
def demo_project():
    d = FIXTURES / "projects" / "vulnerable-demo"
    return (d / "package.json").read_bytes(), (d / "package-lock.json").read_bytes()


# Minimal OSV records shaped like real api.osv.dev responses.
OSV_RECORDS = {
    "GHSA-35jh-r3h4-6jhm": {
        "id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash", "aliases": ["CVE-2021-23337"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
    },
    "GHSA-xvch-5gv4-984h": {
        "id": "GHSA-xvch-5gv4-984h", "summary": "Prototype Pollution in minimist", "aliases": ["CVE-2021-44906"],
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.4"}]},
                                 {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.6"}]}]}],
    },
}
VULNERABLE = {("lodash", "4.17.20"): ["GHSA-35jh-r3h4-6jhm"], ("minimist", "1.2.5"): ["GHSA-xvch-5gv4-984h"]}


def osv_handler(request: httpx.Request) -> httpx.Response | None:
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        results = [{"vulns": [{"id": v} for v in VULNERABLE.get((q["package"]["name"], q["version"]), [])]}
                   for q in queries]
        return httpx.Response(200, json={"results": results})
    if request.url.path.startswith("/v1/vulns/"):
        return httpx.Response(200, json=OSV_RECORDS[request.url.path.rsplit("/", 1)[1]])
    return None


def registry_handler(packages: dict[tuple[str, str], bytes]):
    """Serve fake npm registry metadata + tarballs; 404 for anything else."""
    tarballs = {f"/tarballs/{n}/{v}.tgz": blob for (n, v), blob in packages.items()}
    meta = {f"/{n}/{v}": (n, v, blob) for (n, v), blob in packages.items()}

    def handle(request: httpx.Request) -> httpx.Response | None:
        if request.url.host != "registry.npmjs.org":
            return None
        path = request.url.path
        if path in tarballs:
            return httpx.Response(200, content=tarballs[path])
        if path not in meta:
            return httpx.Response(404)
        name, ver, blob = meta[path]
        manifest = json.loads(_manifest_from(blob))
        return httpx.Response(200, json={**manifest, "name": name, "version": ver, "dist": {
            "tarball": f"https://registry.npmjs.org/tarballs/{name}/{ver}.tgz", "integrity": integrity(blob)}})
    return handle


def _manifest_from(blob: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        fh = tar.extractfile("package/package.json")
        return fh.read() if fh else b"{}"


@pytest.fixture
def mock_http():
    def build(packages: dict[tuple[str, str], bytes] | None = None) -> httpx.Client:
        reg = registry_handler(packages or {})

        def handler(request: httpx.Request) -> httpx.Response:
            return osv_handler(request) or reg(request) or httpx.Response(404)
        return httpx.Client(transport=httpx.MockTransport(handler))
    return build


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch):
    from tracii.ai import meta_client
    meta_client.VERIFIED.clear()
    for var in ("META_API_KEY", "GLIMMER_BASE_URL", "GLIMMER_MODEL", "SPARK_OPEN_BASE_URL", "SPARK_OPEN_MODEL",
                "ENABLE_REPORT_IMAGES"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OSV_MODE", "api")
    monkeypatch.setenv("GUARDDOG_MODE", "off")
    monkeypatch.setenv("NPM_RESOLVER", "off")
