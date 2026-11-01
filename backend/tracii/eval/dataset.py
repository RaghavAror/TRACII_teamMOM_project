"""Load the chainviz-v2 labelled npm dataset (labels.csv) as detector input.

The dataset ships labels only; package code is fetched here:
- benign: exact name@version from the npm registry through npm_registry.fetch_package
  (integrity-verified, in memory, no install, no scripts);
- malicious: DataDog malicious-software-packages-dataset zips (password "infected"),
  read entry by entry IN MEMORY. Nothing is extracted to disk and nothing runs.
Both become the same PackageFiles the detectors already consume.

Benign packages can be cached as JSON (text files only) so reruns do not refetch; keep the cache
out of git (datasets/ is ignored). Malicious samples are never cached: their code is only ever
held in memory, and the encrypted zip is the only copy on disk.
"""

from __future__ import annotations

import csv
import io
import json
import posixpath
import stat
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

from tracii.intake import npm_registry
from tracii.intake.npm_registry import (JS_FILE_EXT, MAX_FILES, MAX_LARGE_JS, MAX_TEXT_FILE, MAX_UNPACKED, TEXT_EXT,
                                         PackageFiles, UnsafeArchive)

ZIP_PASSWORD = b"infected"   # DataDog's published password for its sample archives
MAX_ZIP = 25 * 1024 * 1024


@dataclass(frozen=True)
class Sample:
    id: str
    label: str            # malicious | benign
    subtype: str          # malicious_intent | compromised_lib | top120 | random_tail | known_install_hook | obscure_recent
    package: str
    version: str
    split: str            # dev | test
    ref: str              # tarball URL (benign) or "DataDog/<repo>:<path in repo>" (malicious)
    discovery_date: str = ""

    @property
    def group(self) -> str:
        return f"{self.label}/{self.subtype}"

    @property
    def datadog_path(self) -> str | None:
        return self.ref.split(":", 1)[1] if self.label == "malicious" and ":" in self.ref else None


def load_labels(path: str | Path, split: str | None = None, label: str | None = None) -> list[Sample]:
    rows = list(csv.DictReader(open(path, newline="")))
    missing = {"id", "label", "subtype", "package", "version", "split", "ref"} - set(rows[0] if rows else {})
    if missing:
        raise ValueError(f"labels file is missing columns: {sorted(missing)}")
    samples = [Sample(id=r["id"], label=r["label"], subtype=r["subtype"], package=r["package"], version=r["version"],
                      split=r["split"], ref=r["ref"], discovery_date=r.get("discovery_date", "")) for r in rows]
    if len({s.id for s in samples}) != len(samples):
        raise ValueError("duplicate sample ids in labels file")
    return [s for s in samples if (split is None or s.split == split) and (label is None or s.label == label)]


# ---------- cache ----------

def _cache_file(cache_dir: Path, sample: Sample) -> Path:
    return cache_dir / sample.label / f"{sample.id}.json"


def cache_get(cache_dir: Path | None, sample: Sample) -> PackageFiles | None:
    if not cache_dir or sample.label != "benign":
        return None
    p = _cache_file(cache_dir, sample)
    if not p.is_file():
        return None
    d = json.loads(p.read_text())
    return PackageFiles(name=d["name"], version=d["version"], manifest=d["manifest"], files=d["files"],
                        skipped=d["skipped"], large=d.get("large", {}))


def cache_put(cache_dir: Path | None, sample: Sample, pkg: PackageFiles) -> None:
    if not cache_dir or sample.label != "benign":
        return
    p = _cache_file(cache_dir, sample)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(pkg)))


# ---------- malicious: DataDog zip, read in memory ----------

def _zip_rel(raw: str) -> str:
    name = raw.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchive(f"absolute path in archive: {raw!r}")
    norm = posixpath.normpath(name)
    if norm == ".." or norm.startswith("../"):
        raise UnsafeArchive(f"path traversal in archive: {raw!r}")
    return norm


def read_package_zip(blob: bytes, name: str, version: str, password: bytes | None = ZIP_PASSWORD) -> PackageFiles:
    """Package text from a (possibly ZipCrypto-encrypted) zip, without writing anything to disk.

    The package root is the shallowest directory holding a package.json; files outside it are ignored.
    """
    if len(blob) > MAX_ZIP:
        raise UnsafeArchive("zip larger than limit")
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise UnsafeArchive(f"not a zip archive: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise UnsafeArchive("archive has too many entries")
        entries = []
        for info in infos:
            if stat.S_ISLNK(info.external_attr >> 16):
                raise UnsafeArchive(f"link entry rejected: {info.filename!r}")
            if not info.is_dir():
                entries.append((_zip_rel(info.filename), info))
        if sum(i.file_size for _, i in entries) > MAX_UNPACKED:
            raise UnsafeArchive("archive expands beyond size limit")
        manifests = sorted((p for p, _ in entries if posixpath.basename(p) == "package.json"),
                           key=lambda p: (p.count("/"), p))
        if not manifests:
            raise UnsafeArchive("no package.json in archive")
        root = posixpath.dirname(manifests[0])
        prefix = f"{root}/" if root else ""

        def read(info: zipfile.ZipInfo) -> bytes:
            try:
                return zf.read(info, pwd=password)
            except NotImplementedError as exc:   # e.g. AES encryption: zipfile only does ZipCrypto
                raise UnsafeArchive(f"unsupported zip encryption: {exc}") from exc
            except RuntimeError as exc:
                raise UnsafeArchive(f"cannot decrypt archive: {exc}") from exc

        files, skipped, large, manifest = {}, [], {}, {}
        for path, info in entries:
            if not path.startswith(prefix):
                continue
            rel = path[len(prefix):]
            if info.file_size > MAX_TEXT_FILE or not rel.lower().endswith(TEXT_EXT):
                skipped.append(rel)
                if info.file_size <= MAX_LARGE_JS and rel.lower().endswith(JS_FILE_EXT):
                    large[rel] = read(info)[:MAX_LARGE_JS].decode("utf-8", errors="replace")
                continue
            files[rel] = read(info)[:MAX_TEXT_FILE].decode("utf-8", errors="replace")
        try:
            manifest = json.loads(files.get("package.json", "{}"))
        except json.JSONDecodeError:
            manifest = {}
        if not isinstance(manifest, dict):
            manifest = {}
    return PackageFiles(name=name, version=version, manifest=manifest, files=files, skipped=skipped, large=large)


# ---------- loading ----------

class SampleUnavailable(Exception):
    """The sample's code could not be obtained. Never counted as a detector result."""


def load_sample(sample: Sample, client: httpx.Client, cache_dir: Path | None = None,
                malicious_root: Path | None = None) -> PackageFiles:
    if cached := cache_get(cache_dir, sample):
        return cached
    try:
        if sample.label == "benign":
            pkg = npm_registry.fetch_package(sample.package, sample.version, client)
        else:
            if not malicious_root:
                raise SampleUnavailable("malicious samples need --malicious-root (DataDog dataset checkout)")
            zpath = malicious_root / sample.datadog_path
            if not zpath.is_file():
                raise SampleUnavailable(f"zip not found: {sample.datadog_path}")
            pkg = read_package_zip(zpath.read_bytes(), sample.package, sample.version)
    except SampleUnavailable:
        raise
    except (httpx.HTTPError, UnsafeArchive, npm_registry.IntegrityError, OSError) as exc:
        raise SampleUnavailable(f"{type(exc).__name__}: {str(exc)[:160]}") from exc
    cache_put(cache_dir, sample, pkg)
    return pkg
