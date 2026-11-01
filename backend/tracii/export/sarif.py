"""SARIF 2.1.0 export, shaped for GitHub code scanning.

- One rule per advisory / detector rule; one result per finding.
- The primary location is the package's entry in package-lock.json (the file in the
  user's repository that pulls the package in). Code evidence lives inside the npm
  tarball, not the repository, so it goes into the message and result properties.
- `security-severity` follows GitHub's bands (>=9 critical, 7-8.9 high, 4-6.9 medium,
  0.1-3.9 low). Unknown severity gets no score rather than an invented one.
- Categories stay separate: each result is tagged with its category.
- Failed or skipped checks become tool notifications, so an incomplete scan cannot
  pass for a clean one.
"""

from __future__ import annotations

import hashlib
import re

from tracii import __version__
from tracii.evidence.schema import Finding, ScanResult, Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/RaghavAror/TRACII_teamMOM_project"

SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}
LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note",
         Severity.INFO: "note", Severity.UNKNOWN: "warning"}


def lockfile_lines(lockfile: str, result: ScanResult) -> dict[tuple[str, str], int]:
    """(name, version) -> 1-based line of its first entry in the lockfile; missing if not found."""
    lines = lockfile.splitlines()
    out: dict[tuple[str, str], int] = {}
    for node in result.inventory.packages:
        ident = (node.name, node.version)
        if ident in out:
            continue
        # v2/v3 key the entry by lockfile path; v1 nests entries keyed by bare name.
        keys = (node.path, node.name) if result.inventory.lockfile_version < 2 else (node.path,)
        for key in keys:
            pat = re.compile(r'^\s*"' + re.escape(key) + r'"\s*:\s*\{')
            ver = f'"version": "{node.version}"'
            hit = next((i for i, ln in enumerate(lines)
                        if pat.match(ln) and any(ver in x for x in lines[i:i + 6])), None)
            if hit is not None:
                out[ident] = hit + 1
                break
    return out


def _rule(f: Finding) -> dict:
    sev = SECURITY_SEVERITY.get(f.severity)
    url = next((e.url for e in f.evidence if e.url), None)
    rule = {
        "id": f.rule_or_advisory,
        "name": re.sub(r"[^A-Za-z0-9]+", "", f.rule_or_advisory.title()) or "TraciiFinding",
        "shortDescription": {"text": f.title[:200]},
        "fullDescription": {"text": f"{f.title} (source: {f.source}, category: {f.category.value})"},
        "defaultConfiguration": {"level": LEVEL[f.severity]},
        "properties": {"tags": ["security", "supply-chain", f.category.value, *f.aliases],
                       "precision": {"high": "high", "medium": "medium", "low": "low"}[f.confidence.value]},
    }
    if sev:
        rule["properties"]["security-severity"] = sev
    if url:
        rule["helpUri"] = url
    return rule


def _message(f: Finding) -> str:
    parts = [f"{f.title}: {f.package}@{f.version} ({f.category.value}, severity {f.severity.value}, "
             f"confidence {f.confidence.value}, source {f.source})."]
    if f.paths:
        p = f.paths[0]
        parts.append("Path: " + " > ".join(p.nodes) + (" (dev only)." if p.dev_only else "."))
    if f.fixed_versions:
        parts.append("Fixed in: " + ", ".join(f.fixed_versions[:5]) + ".")
    for e in f.evidence[:3]:
        loc = f" [{e.file}:{e.line}]" if e.file and e.line else (f" [{e.file}]" if e.file else "")
        parts.append(f"Evidence {e.id}{loc}: {e.summary}")
    parts.extend(f.limitations[:2])
    return " ".join(parts)


def to_sarif(result: ScanResult, lockfile: str = "", lockfile_uri: str = "package-lock.json") -> dict:
    lines = lockfile_lines(lockfile, result) if lockfile else {}
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rules.setdefault(f.rule_or_advisory, _rule(f))
        region = {"startLine": lines.get((f.package, f.version), 1)}
        fingerprint = hashlib.sha256(f"{f.key}|{f.version}".encode()).hexdigest()
        res = {
            "ruleId": f.rule_or_advisory,
            "ruleIndex": list(rules).index(f.rule_or_advisory),
            "level": LEVEL[f.severity],
            "message": {"text": _message(f)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": lockfile_uri}, "region": region},
                           "logicalLocations": [{"name": f"{f.package}@{f.version}", "kind": "package"}]}],
            "partialFingerprints": {"traciiFinding/v1": fingerprint},
            "properties": {
                "tracii_finding_id": f.id, "category": f.category.value, "severity": f.severity.value,
                "confidence": f.confidence.value, "package": f.package, "version": f.version,
                "fixed_versions": f.fixed_versions,
                "evidence": [e.model_dump(exclude={"snippet"}, exclude_none=True) for e in f.evidence],
            },
        }
        if sev := SECURITY_SEVERITY.get(f.severity):
            res["properties"]["security-severity"] = sev
        results.append(res)

    notifications = [{"level": "error" if c.status == "failed" else "note",
                      "message": {"text": f"Check '{c.name}' {c.status}: {c.detail}"[:500]}}
                     for c in result.checks if c.status != "ran"]
    run = {
        "tool": {"driver": {"name": "Tracii", "version": __version__, "semanticVersion": __version__,
                            "informationUri": INFO_URI, "rules": list(rules.values())}},
        "automationDetails": {"id": f"tracii/{result.source.label}/"},
        "invocations": [{"executionSuccessful": not any(c.status == "failed" for c in result.checks),
                         "toolExecutionNotifications": notifications}],
        "results": results,
        "properties": {"scan_id": result.scan_id, "created_at": result.created_at,
                       "checks": [c.model_dump() for c in result.checks],
                       "note": "Results say what these checks detected; no result is not a guarantee of safety."},
    }
    if result.source.commit_sha:
        run["versionControlProvenance"] = [{"repositoryUri": f"https://github.com/{result.source.label}",
                                            "revisionId": result.source.commit_sha,
                                            **({"branch": result.source.ref} if result.source.ref else {})}]
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
