"""Known-vulnerability channel (OSV). Kept separate from malware detection.

Two interchangeable backends produce identical Finding objects:
- `cli`: OSV-Scanner v2 binary (`osv-scanner scan source -L <lockfile> --format json`)
- `api`: OSV.dev /v1/querybatch + /v1/vulns/{id} using our exact inventory versions

Matching is always on exact installed version (chainviz matched by name only,
which flags every historical CVE of a package regardless of version).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

from tracii.evidence.schema import (
    Category, CheckRun, Confidence, Evidence, Finding, Inventory, Severity, make_id,
)

OSV_API = os.environ.get("OSV_API_URL", "https://api.osv.dev")
BATCH = 500
_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _severity(vuln: dict) -> Severity:
    db = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db.upper() in _SEV:
        return _SEV[db.upper()]
    return Severity.UNKNOWN  # CVSS vector parsing intentionally deferred; shown raw in evidence


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    fixed: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "npm" or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return fixed


def _affected_ranges(vuln: dict, name: str) -> str:
    parts = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            evs = rng.get("events") or []
            intro = next((e["introduced"] for e in evs if "introduced" in e), "?")
            end = next((f"<{e['fixed']}" for e in evs if "fixed" in e),
                       next((f"<={e['last_affected']}" for e in evs if "last_affected" in e), ""))
            parts.append(f">={intro} {end}".strip())
    return ", ".join(parts) or "see advisory"


def vuln_to_finding(vuln: dict, name: str, version: str, source: str) -> Finding:
    vid = vuln.get("id", "UNKNOWN")
    refs = vuln.get("references") or []
    advisory_url = next((r.get("url") for r in refs if r.get("type") == "ADVISORY"),
                        f"https://osv.dev/vulnerability/{vid}")
    cvss = ", ".join(s.get("score", "") for s in vuln.get("severity") or [])
    fid = make_id("vuln", name, version, vid)
    return Finding(
        id=fid,
        category=Category.VULNERABILITY,
        source=source,
        rule_or_advisory=vid,
        title=vuln.get("summary") or (vuln.get("details") or vid)[:140],
        package=name,
        version=version,
        severity=_severity(vuln),
        confidence=Confidence.HIGH,  # exact version matched against a published advisory
        aliases=list(vuln.get("aliases") or []),
        fixed_versions=_fixed_versions(vuln, name),
        evidence=[Evidence(
            id=f"{fid}-adv",
            kind="advisory",
            summary=f"{vid} affects {name} {_affected_ranges(vuln, name)}; installed {version}"
                    + (f"; CVSS {cvss}" if cvss else ""),
            url=advisory_url,
            snippet=(vuln.get("details") or "")[:1500] or None,
        )],
        limitations=[
            "Advisory match shows the installed version is in an affected range; "
            "it does not prove the vulnerable code path is used by this app.",
        ],
    )


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge records for the same package@version that share an ID or alias."""
    kept: list[Finding] = []
    for f in findings:
        ids = {f.rule_or_advisory, *f.aliases}
        dup = next((k for k in kept if k.package == f.package and k.version == f.version
                    and ids & {k.rule_or_advisory, *k.aliases}), None)
        if dup:
            dup.aliases = sorted({*dup.aliases, *ids} - {dup.rule_or_advisory})
            dup.fixed_versions = sorted({*dup.fixed_versions, *f.fixed_versions})
        else:
            kept.append(f)
    return kept


def scan_api(inventory: Inventory, client: httpx.Client | None = None) -> tuple[list[Finding], CheckRun]:
    own = client is None
    client = client or httpx.Client(timeout=30)
    try:
        pkgs = sorted({(p.name, p.version) for p in inventory.packages if p.version})
        hits: list[tuple[str, str, str]] = []
        for i in range(0, len(pkgs), BATCH):
            chunk = pkgs[i:i + BATCH]
            body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]}
            resp = client.post(f"{OSV_API}/v1/querybatch", json=body)
            resp.raise_for_status()
            for (n, v), res in zip(chunk, resp.json().get("results", [])):
                for vuln in res.get("vulns") or []:
                    hits.append((n, v, vuln["id"]))
        details: dict[str, dict] = {}
        findings = []
        for n, v, vid in hits:
            if vid not in details:
                r = client.get(f"{OSV_API}/v1/vulns/{vid}")
                r.raise_for_status()
                details[vid] = r.json()
            findings.append(vuln_to_finding(details[vid], n, v, "osv-api"))
        return dedupe(findings), CheckRun(name="osv", status="ran", detail="OSV.dev API (exact versions)",
                                          packages_checked=len(pkgs))
    except httpx.HTTPError as exc:
        return [], CheckRun(name="osv", status="failed", detail=f"OSV API error: {exc}")
    finally:
        if own:
            client.close()


def scan_cli(lockfile_bytes: bytes, binary: str) -> tuple[list[Finding], CheckRun]:
    with tempfile.TemporaryDirectory(prefix="tracii-osv-") as tmp:
        lock = Path(tmp) / "package-lock.json"
        lock.write_bytes(lockfile_bytes)
        proc = subprocess.run([binary, "scan", "source", "-L", str(lock), "--format", "json"],
                              capture_output=True, text=True, timeout=300)
    if proc.returncode not in (0, 1):  # 1 == vulnerabilities found
        return [], CheckRun(name="osv", status="failed", detail=f"osv-scanner exit {proc.returncode}: {proc.stderr[:300]}")
    data = json.loads(proc.stdout or "{}")
    findings, count = [], 0
    for res in data.get("results") or []:
        for pkg in res.get("packages") or []:
            info = pkg.get("package") or {}
            count += 1
            for vuln in pkg.get("vulnerabilities") or []:
                findings.append(vuln_to_finding(vuln, info.get("name", ""), info.get("version", ""), "osv-scanner"))
    return dedupe(findings), CheckRun(name="osv", status="ran", detail="OSV-Scanner CLI", packages_checked=count)


def scan(inventory: Inventory, lockfile_bytes: bytes, client: httpx.Client | None = None) -> tuple[list[Finding], CheckRun]:
    mode = os.environ.get("OSV_MODE", "auto")
    binary = os.environ.get("OSV_SCANNER_BIN") or shutil.which("osv-scanner")
    if mode == "cli" or (mode == "auto" and binary and client is None):
        if not binary:
            return [], CheckRun(name="osv", status="not_configured", detail="OSV_MODE=cli but osv-scanner not found")
        findings, check = scan_cli(lockfile_bytes, binary)
        # the CLI only lists packages that have vulnerabilities; report what was actually checked
        if check.status == "ran":
            check.packages_checked = len({(p.name, p.version) for p in inventory.packages})
        return findings, check
    return scan_api(inventory, client)
