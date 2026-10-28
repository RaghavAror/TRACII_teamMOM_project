"""Fetch npm package tarballs as UNTRUSTED data.

- Never installs and never runs lifecycle scripts. Files are kept in memory;
  the only on-disk copy is a temp dir mounted read-only into GuardDog.
- Verifies the registry `dist.integrity` (sha512) before reading anything.
- Extracts in memory, rejecting links, absolute paths, `..`, and oversized archives.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import posixpath
import tarfile
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

REGISTRY = os.environ.get("NPM_REGISTRY_URL", "https://registry.npmjs.org")
MAX_TARBALL = 25 * 1024 * 1024
MAX_UNPACKED = 80 * 1024 * 1024
MAX_FILES = 5000
MAX_TEXT_FILE = 1024 * 1024
TEXT_EXT = (".js", ".cjs", ".mjs", ".ts", ".json", ".sh", ".py", ".jsx", ".tsx", ".md", ".txt", ".yml", ".yaml")


class UnsafeArchive(ValueError):
    pass


class IntegrityError(ValueError):
    pass


@dataclass
class PackageFiles:
    name: str
    version: str
    manifest: dict
    files: dict[str, str] = field(default_factory=dict)   # relative path -> text
    skipped: list[str] = field(default_factory=list)


def verify_integrity(blob: bytes, integrity: str | None) -> None:
    if not integrity:
        raise IntegrityError("registry did not provide an integrity hash; refusing to analyse")
    algo, _, expected = integrity.partition("-")
    if algo not in ("sha512", "sha384", "sha256"):
        raise IntegrityError(f"unsupported integrity algorithm {algo}")
    actual = base64.b64encode(hashlib.new(algo, blob).digest()).decode()
    if actual != expected:
        raise IntegrityError("tarball integrity mismatch")


def _safe_member_name(raw: str) -> str:
    name = raw.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchive(f"absolute path in archive: {raw!r}")
    norm = posixpath.normpath(name)
    if norm == ".." or norm.startswith("../"):
        raise UnsafeArchive(f"path traversal in archive: {raw!r}")
    # npm tarballs nest everything under one top-level dir (usually "package/")
    parts = norm.split("/", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def extract_in_memory(blob: bytes) -> tuple[dict[str, str], list[str]]:
    files: dict[str, str] = {}
    skipped: list[str] = []
    total = 0
    try:
        tar = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    except tarfile.TarError as exc:
        raise UnsafeArchive(f"not a gzip tar archive: {exc}") from exc
    with tar:
        for count, member in enumerate(tar):
            if count >= MAX_FILES:
                raise UnsafeArchive("archive has too many entries")
            if member.issym() or member.islnk():
                raise UnsafeArchive(f"link entry rejected: {member.name!r}")
            if not member.isfile():
                continue
            rel = _safe_member_name(member.name)
            total += member.size
            if total > MAX_UNPACKED:
                raise UnsafeArchive("archive expands beyond size limit")
            if member.size > MAX_TEXT_FILE or not rel.lower().endswith(TEXT_EXT):
                skipped.append(rel)
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            files[rel] = fh.read(MAX_TEXT_FILE).decode("utf-8", errors="replace")
    return files, skipped


def registry_url(name: str) -> str:
    return f"{REGISTRY}/{quote(name, safe='@')}"


def fetch_version_meta(name: str, version: str, client: httpx.Client) -> dict:
    resp = client.get(f"{registry_url(name)}/{quote(version)}")
    resp.raise_for_status()
    return resp.json()


def fetch_package(name: str, version: str, client: httpx.Client) -> PackageFiles:
    meta = fetch_version_meta(name, version, client)
    dist = meta.get("dist") or {}
    tarball_url = dist.get("tarball")
    if not tarball_url or not tarball_url.startswith(REGISTRY):
        raise UnsafeArchive(f"unexpected tarball location: {tarball_url!r}")
    with client.stream("GET", tarball_url) as resp:
        resp.raise_for_status()
        chunks, size = [], 0
        for chunk in resp.iter_bytes():
            size += len(chunk)
            if size > MAX_TARBALL:
                raise UnsafeArchive("tarball larger than limit")
            chunks.append(chunk)
    blob = b"".join(chunks)
    verify_integrity(blob, dist.get("integrity"))
    files, skipped = extract_in_memory(blob)
    return PackageFiles(name=name, version=version, manifest=meta, files=files, skipped=skipped)


def load_local_package(directory: str) -> PackageFiles:
    """Load an on-disk package directory (test fixtures / already-extracted trees) as data."""
    import json
    from pathlib import Path

    root = Path(directory)
    manifest = json.loads((root / "package.json").read_text())
    files, skipped = {}, []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if p.stat().st_size > MAX_TEXT_FILE or not rel.lower().endswith(TEXT_EXT):
            skipped.append(rel)
            continue
        files[rel] = p.read_text(errors="replace")
    return PackageFiles(name=manifest.get("name", root.name), version=manifest.get("version", "0.0.0"),
                        manifest=manifest, files=files, skipped=skipped)
