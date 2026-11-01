import importlib.util
import io
import json
import struct
import zipfile
import zlib

import pytest

from tests.conftest import FIXTURES, fixture_tarball
from tracii.eval import dataset
from tracii.eval.dataset import Sample, SampleUnavailable
from tracii.intake.npm_registry import UnsafeArchive

LABEL_COLS = "id,label,subtype,package,version,discovery_date,source,split,install_hooks,signals,n_files,total_bytes,ref"


def write_labels(path, rows):
    lines = [LABEL_COLS] + [f"{r[0]},{r[1]},{r[2]},{r[3]},{r[4]},,src,{r[5]},,,0,0,{r[6]}" for r in rows]
    path.write_text("\n".join(lines) + "\n")
    return path


# ---------- ZipCrypto writer (zipfile can read these archives but not create them) ----------

_CRC = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC[_i] = _c


def _zipcrypto(data: bytes, password: bytes, crc: int) -> bytes:
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(b):
        keys[0] = (keys[0] >> 8) ^ _CRC[(keys[0] ^ b) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = (keys[2] >> 8) ^ _CRC[(keys[2] ^ (keys[1] >> 24)) & 0xFF]

    def stream():
        t = (keys[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    for b in password:
        update(b)
    out = bytearray()
    for p in bytes(11) + bytes([crc >> 24]) + data:   # 12-byte header, last byte = CRC check
        out.append(p ^ stream())
        update(p)
    return bytes(out)


def encrypted_zip(files: dict[str, bytes], password: bytes = b"infected") -> bytes:
    buf, central = io.BytesIO(), []
    for name, data in files.items():
        crc, raw = zlib.crc32(data), name.encode()
        enc = _zipcrypto(data, password, crc)
        offset = buf.tell()
        buf.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0, crc, len(enc), len(data), len(raw), 0))
        buf.write(raw + enc)
        central.append(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0, crc, len(enc), len(data),
                                   len(raw), 0, 0, 0, 0, 0, offset) + raw)
    start = buf.tell()
    for c in central:
        buf.write(c)
    buf.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central), len(central), buf.tell() - start, start, 0))
    return buf.getvalue()


def fixture_files(name: str, root: str) -> dict[str, bytes]:
    d = FIXTURES / "packages" / name
    return {f"{root}/{p.relative_to(d).as_posix()}": p.read_bytes() for p in d.rglob("*") if p.is_file()}


# ---------- labels ----------

def test_load_labels_filters_and_validates(tmp_path):
    p = write_labels(tmp_path / "l.csv", [("M1", "malicious", "malicious_intent", "evil", "1.0.0", "dev", "DataDog/x:a/b.zip"),
                                         ("B1", "benign", "top120", "@s/ok", "2.0.0", "test", "https://r/x.tgz")])
    assert [s.id for s in dataset.load_labels(p)] == ["M1", "B1"]
    assert [s.id for s in dataset.load_labels(p, split="dev")] == ["M1"]
    m = dataset.load_labels(p, label="malicious")[0]
    assert m.group == "malicious/malicious_intent" and m.datadog_path == "a/b.zip"
    assert dataset.load_labels(p, label="benign")[0].datadog_path is None
    dup = write_labels(tmp_path / "d.csv", [("X", "benign", "t", "a", "1", "dev", "u")] * 2)
    with pytest.raises(ValueError, match="duplicate"):
        dataset.load_labels(dup)
    (tmp_path / "bad.csv").write_text("id,label\nX,benign\n")
    with pytest.raises(ValueError, match="missing columns"):
        dataset.load_labels(tmp_path / "bad.csv")


# ---------- zips ----------

def test_encrypted_datadog_style_zip_is_read_in_memory():
    blob = encrypted_zip(fixture_files("fake-exfil", "fake-exfil/1.0.0/package") | {"fake-exfil/1.0.0/logo.png": b"\x89PNG"})
    with pytest.raises(RuntimeError):   # proves the archive really is encrypted
        zipfile.ZipFile(io.BytesIO(blob)).read("fake-exfil/1.0.0/package/package.json")
    pkg = dataset.read_package_zip(blob, "fake-exfil", "1.0.0")
    assert set(pkg.files) == {"package.json", "index.js", "setup.js"}
    assert pkg.manifest["scripts"]["postinstall"] and pkg.skipped == []   # logo.png sits outside the package root
    with pytest.raises(UnsafeArchive, match="decrypt"):
        dataset.read_package_zip(blob, "fake-exfil", "1.0.0", password=b"wrong")


def test_zip_root_is_shallowest_package_json():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("pkg/package.json", '{"name":"outer"}')
        z.writestr("pkg/index.js", "module.exports = 1")
        z.writestr("pkg/node_modules/dep/package.json", '{"name":"inner"}')
        z.writestr("pkg/bin/tool.exe", "MZ")
    pkg = dataset.read_package_zip(buf.getvalue(), "outer", "1.0.0", password=None)
    assert pkg.manifest["name"] == "outer" and "node_modules/dep/package.json" in pkg.files
    assert pkg.skipped == ["bin/tool.exe"]


@pytest.mark.parametrize("entry", ["../escape/package.json", "/abs/package.json"])
def test_zip_traversal_rejected(entry):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(entry, "{}")
    with pytest.raises(UnsafeArchive):
        dataset.read_package_zip(buf.getvalue(), "x", "1", password=None)


def test_zip_symlink_and_missing_manifest_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        link = zipfile.ZipInfo("p/package.json")
        link.external_attr = (0o120777 << 16)
        z.writestr(link, "/etc/passwd")
    with pytest.raises(UnsafeArchive, match="link"):
        dataset.read_package_zip(buf.getvalue(), "x", "1", password=None)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("p/index.js", "1")
    with pytest.raises(UnsafeArchive, match="no package.json"):
        dataset.read_package_zip(buf.getvalue(), "x", "1", password=None)
    with pytest.raises(UnsafeArchive, match="not a zip"):
        dataset.read_package_zip(b"nope", "x", "1")


# ---------- load_sample + cache ----------

def test_benign_sample_fetch_cache_and_unavailable(tmp_path, mock_http):
    blob = fixture_tarball(FIXTURES / "packages" / "benign-http-client")
    client = mock_http({("benign-http-client", "1.0.0"): blob})
    ok = Sample("B1", "benign", "top120", "benign-http-client", "1.0.0", "dev", "u")
    pkg = dataset.load_sample(ok, client, tmp_path)
    assert "index.js" in pkg.files and (tmp_path / "benign" / "B1.json").is_file()
    cached = dataset.load_sample(ok, mock_http({}), tmp_path)   # registry now empty: served from cache
    assert cached.files == pkg.files and cached.manifest == pkg.manifest
    with pytest.raises(SampleUnavailable, match="HTTPStatusError"):
        dataset.load_sample(Sample("B2", "benign", "top120", "gone", "9.9.9", "dev", "u"), client, tmp_path)


def test_malicious_sample_needs_local_root(tmp_path, mock_http):
    s = Sample("M1", "malicious", "malicious_intent", "fake-exfil", "1.0.0", "dev", "DataDog/x:samples/npm/m.zip")
    with pytest.raises(SampleUnavailable, match="malicious-root"):
        dataset.load_sample(s, mock_http(), None)
    with pytest.raises(SampleUnavailable, match="zip not found"):
        dataset.load_sample(s, mock_http(), None, malicious_root=tmp_path)
    (tmp_path / "samples/npm").mkdir(parents=True)
    (tmp_path / "samples/npm/m.zip").write_bytes(encrypted_zip(fixture_files("fake-exfil", "package")))
    assert "setup.js" in dataset.load_sample(s, mock_http(), None, malicious_root=tmp_path).files


# ---------- evaluation script ----------

def _script():
    path = FIXTURES.parent / "scripts" / "evaluate_dataset.py"
    spec = importlib.util.spec_from_file_location("evaluate_dataset", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_wilson_interval():
    ev = _script()
    assert ev.wilson(0, 0) is None
    lo, hi = ev.wilson(0, 20)
    assert lo == 0.0 and 0.1 < hi < 0.2      # zero false alarms out of 20 still allows up to ~16%
    lo, hi = ev.wilson(10, 20)
    assert lo < 0.5 < hi


def test_evaluate_script_end_to_end_offline(tmp_path):
    ev = _script()
    root = tmp_path / "dd"
    rows = []
    for i, name in enumerate(["fake-exfil", "obfuscated-loader", "fake-exfil"]):   # 2 copies of the same code
        rel = f"samples/npm/{name}-{i}.zip"
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(encrypted_zip(fixture_files(name, "package")))
        rows.append((f"M{i}", "malicious", "malicious_intent", name, "1.0.0", "dev", f"DataDog/x:{rel}"))
    rows.append(("M9", "malicious", "compromised_lib", "missing", "1.0.0", "dev", "DataDog/x:samples/npm/none.zip"))
    rows.append(("T1", "malicious", "malicious_intent", "later", "1.0.0", "test", "DataDog/x:samples/npm/t.zip"))
    labels = write_labels(tmp_path / "labels.csv", rows)
    out = tmp_path / "res.json"
    with pytest.raises(SystemExit):
        ev.main(["--labels", str(labels), "--split", "test"])          # locked without --final
    assert ev.main(["--labels", str(labels), "--malicious-root", str(root), "--cache", str(tmp_path / "c"),
                    "--out", str(out)]) == 0
    res = json.loads(out.read_text())
    assert res["split"] == "dev" and res["scored"] == 3 and res["unavailable"] == 1
    assert res["unavailable_samples"][0]["id"] == "M9"                 # missing code is never a "miss"
    s = res["results"]["static"]
    assert s["malicious/ALL"]["flagged"] == 3 and s["malicious/ALL"]["n"] == 3
    assert s["malicious/ALL"]["unique_code"]["n"] == 2                 # the duplicate collapses into one cluster
    assert {r["id"]: r["static_rules"] for r in res["rows"]}["M0"] == ["TRACII-CHAIN-EXFIL"]
    assert not any(p.name == "res.json" for p in (FIXTURES.parent / "results").iterdir())


def test_guarddog_failure_is_excluded_not_a_crash(monkeypatch):
    ev = _script()
    from tracii.intake.npm_registry import load_local_package

    def boom(pkg):
        raise RuntimeError("GuardDog not available")
    monkeypatch.setattr(ev.guarddog, "run_guarddog", boom)
    s = Sample("M1", "malicious", "malicious_intent", "fake-exfil", "1.0.0", "dev", "x")
    row = ev.evaluate(s, load_local_package(str(FIXTURES / "packages" / "fake-exfil")), use_guarddog=True)
    assert row["static_flagged"] and row["guarddog_flagged"] is None and "not available" in row["guarddog_error"]
    res = ev.summarise([row], ["static", "guarddog", "combined"])
    assert res["static"]["malicious/ALL"]["n"] == 1
    assert res["guarddog"] == {"_not_run": 1} and res["combined"] == {"_not_run": 1}


def test_malicious_code_is_never_cached_to_disk(tmp_path, mock_http):
    (tmp_path / "dd/samples").mkdir(parents=True)
    (tmp_path / "dd/samples/m.zip").write_bytes(encrypted_zip(fixture_files("fake-exfil", "package")))
    s = Sample("M1", "malicious", "malicious_intent", "fake-exfil", "1.0.0", "dev", "DataDog/x:samples/m.zip")
    cache = tmp_path / "cache"
    assert "setup.js" in dataset.load_sample(s, mock_http(), cache, malicious_root=tmp_path / "dd").files
    assert not cache.exists() or not any(cache.rglob("*"))
