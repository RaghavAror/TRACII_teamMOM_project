"""Scan pipeline: inventory -> OSV -> prioritised malware checks -> impact -> store.

Cheap deterministic checks run on every package; tarball-level checks
(Tracii static rules + GuardDog) run only on a prioritised subset so scans stay
fast. Whatever is skipped is recorded in `checks` and shown to the user.
"""

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from tracii.detect import guarddog, osv, static_rules
from tracii.evidence.schema import CheckRun, Finding, Inventory, PackageNode, ScanResult, ScanSource
from tracii.impact.paths import DependencyGraph
from tracii.intake import npm_registry
from tracii.inventory.lockfile import build_inventory

DEEP_SCAN_LIMIT = int(os.environ.get("DEEP_SCAN_LIMIT", "15"))


@dataclass
class ScanRecord:
    scan_id: str
    status: str = "running"            # running | done | failed
    progress: list[str] = field(default_factory=list)
    result: ScanResult | None = None
    error: str | None = None
    package_json: str = ""
    lockfile: bytes = b""
    package_files: dict[str, npm_registry.PackageFiles] = field(default_factory=dict)  # "name@ver" -> files
    deep_limit: int = DEEP_SCAN_LIMIT


class Store:
    """In-memory scan store. Scan history is not persisted (no database in the MVP)."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}
        self._lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=2)

    def new(self) -> ScanRecord:
        rec = ScanRecord(scan_id=uuid.uuid4().hex[:12])
        with self._lock:
            self._scans[rec.scan_id] = rec
        return rec

    def get(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)


STORE = Store()


def select_deep_targets(inv: Inventory, limit: int) -> list[PackageNode]:
    seen, ordered = set(), []
    ranked = sorted(inv.packages, key=lambda p: (not p.has_install_script, not p.direct, p.dev, p.path))
    for p in ranked:
        if (p.name, p.version) in seen:
            continue
        seen.add((p.name, p.version))
        ordered.append(p)
    return ordered[:limit]


def attach_paths(findings: list[Finding], graph: DependencyGraph) -> None:
    for f in findings:
        f.paths = graph.paths_for(f.package, f.version)
        if f.paths and all(p.dev_only for p in f.paths):
            f.limitations.append("Reached only through devDependencies: not shipped in a production install.")
        if f.paths:
            f.limitations.append("Dependency-path reachability only; whether app code calls the affected "
                                 "functionality was not analysed.")


def run_scan(rec: ScanRecord, source: ScanSource, package_json: bytes, lockfile: bytes,
             http: httpx.Client | None = None, deep_limit: int | None = None,
             parent_scan_id: str | None = None) -> ScanResult:
    own = http is None
    http = http or httpx.Client(timeout=30, follow_redirects=False)
    try:
        rec.package_json, rec.lockfile = package_json.decode(), lockfile
        rec.progress.append("Building dependency inventory from lockfile")
        inv = build_inventory(package_json, lockfile)
        checks: list[CheckRun] = [CheckRun(name="inventory", status="ran",
                                           detail=f"lockfile v{inv.lockfile_version}", packages_checked=len(inv.packages))]

        rec.progress.append(f"Checking {len(inv.packages)} packages against OSV advisories")
        vulns, osv_check = osv.scan(inv, lockfile, client=None if own else http)
        checks.append(osv_check)

        limit = DEEP_SCAN_LIMIT if deep_limit is None else deep_limit
        rec.deep_limit = limit
        targets = select_deep_targets(inv, limit)
        rec.progress.append(f"Fetching {len(targets)} prioritised package tarballs (integrity-verified, not installed)")
        fetched, fetch_errors = [], []
        for node in targets:
            try:
                pf = npm_registry.fetch_package(node.name, node.version, http)
                rec.package_files[f"{pf.name}@{pf.version}"] = pf
                fetched.append(pf)
            except (httpx.HTTPError, npm_registry.UnsafeArchive, npm_registry.IntegrityError) as exc:
                fetch_errors.append(f"{node.name}@{node.version}: {str(exc)[:100]}")

        rec.progress.append("Running Tracii static behaviour rules")
        malicious: list[Finding] = []
        for pf in fetched:
            malicious.extend(static_rules.analyze_package(pf))
        skipped = len({(p.name, p.version) for p in inv.packages}) - len(targets)
        checks.append(CheckRun(
            name="tracii-static", status="ran" if fetched or not targets else "failed",
            detail=f"{len(fetched)} packages analysed; {skipped} not selected (limit {limit})"
                   + (f"; fetch errors: {'; '.join(fetch_errors[:3])}" if fetch_errors else ""),
            packages_checked=len(fetched)))

        rec.progress.append("Running GuardDog on the same packages")
        gd_findings, gd_check = guarddog.scan_packages(fetched)
        malicious.extend(gd_findings)
        checks.append(gd_check)
        checks.append(CheckRun(name="repository-posture", status="skipped",
                               detail="OpenSSF Scorecard integration is optional (milestone 6)"))

        rec.progress.append("Tracing dependency paths")
        findings = vulns + malicious
        attach_paths(findings, DependencyGraph(inv))

        result = ScanResult(scan_id=rec.scan_id, source=source, inventory=inv, findings=findings, checks=checks,
                            created_at=datetime.now(timezone.utc).isoformat(), parent_scan_id=parent_scan_id)
        rec.result, rec.status = result, "done"
        rec.progress.append("Done")
        return result
    except Exception as exc:
        rec.status, rec.error = "failed", str(exc)[:500]
        raise
    finally:
        if own:
            http.close()
