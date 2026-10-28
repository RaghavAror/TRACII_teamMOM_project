"""GuardDog (Apache-2.0, DataDog) as the first-line malicious-package scanner.

We hand GuardDog the same integrity-verified files Tracii already extracted,
written to a throwaway directory. In docker mode the directory is mounted
read-only into a container with `--network none`. GuardDog is static
(Semgrep/YARA rules); package code is never executed.

Output format verified against guarddog v3.2.0:
  {"issues": n, "results": {rule: null | {} | [ {location, code, match, message} ] | str}, "risks": [...]}
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from tracii.evidence.schema import Category, CheckRun, Confidence, Evidence, Finding, Severity, make_id
from tracii.intake.npm_registry import PackageFiles

IMAGE = os.environ.get("GUARDDOG_IMAGE", "ghcr.io/datadog/guarddog:latest")
_RISK_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


def mode() -> str:
    m = os.environ.get("GUARDDOG_MODE", "auto")
    if m != "auto":
        return m
    if shutil.which("guarddog"):
        return "local"
    if shutil.which("docker"):
        return "docker"
    return "off"


def _write_tree(pkg: PackageFiles, root: Path) -> None:
    # Use the author's package.json from the tarball. The registry version doc
    # adds dist/_resolved URLs that trip threat-npm-http-dependency on every package.
    if "package.json" not in pkg.files:
        (root / "package.json").write_text(json.dumps(
            {k: v for k, v in pkg.manifest.items() if not k.startswith("_") and k != "dist"}))
    for rel, text in pkg.files.items():
        dest = (root / rel).resolve()
        if not str(dest).startswith(str(root.resolve())):
            continue  # defence in depth; extract_in_memory already rejects traversal
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)


def run_guarddog(pkg: PackageFiles, timeout: int = 180) -> dict:
    m = mode()
    with tempfile.TemporaryDirectory(prefix="tracii-gd-") as tmp:
        root = Path(tmp) / "pkg"
        root.mkdir()
        _write_tree(pkg, root)
        if m == "local":
            cmd = ["guarddog", "npm", "scan", str(root), "--output-format", "json"]
        elif m == "docker":
            cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                   "-v", f"{root}:/pkg:ro", IMAGE, "npm", "scan", "/pkg", "--output-format", "json"]
        else:
            raise RuntimeError("GuardDog not available")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"guarddog exit {proc.returncode}: {proc.stderr[-300:]}")
    return json.loads(proc.stdout)


def to_findings(report: dict, pkg: PackageFiles) -> list[Finding]:
    risk_sev = {r.get("threat_rule"): _RISK_SEV.get(str(r.get("severity")).lower(), Severity.MEDIUM)
                for r in report.get("risks") or []}
    findings: list[Finding] = []
    capability_ev: list[Evidence] = []
    cap_id = make_id("mal", pkg.name, pkg.version, "guarddog-capabilities")
    lim = ["GuardDog rule matches are risk indicators, not a definitive verdict.",
           "Only text files extracted by Tracii were scanned (binaries skipped)."]

    for rule, hits in sorted((report.get("results") or {}).items()):
        if not hits:
            continue
        if isinstance(hits, list):
            evidence = []
            for i, h in enumerate(hits[:10]):
                file, _, line = str(h.get("location", "")).rpartition(":")
                evidence.append(Evidence(
                    id=f"{make_id('gd', pkg.name, pkg.version, rule)}-e{i}", kind="code",
                    summary=f"{rule}: {h.get('message', '')}".strip(), file=file or None,
                    line=int(line) if line.isdigit() else None, snippet=(h.get("code") or "")[:600]))
            if rule.startswith("capability-"):
                capability_ev.extend(evidence)
                continue
            fid = make_id("mal", pkg.name, pkg.version, f"guarddog:{rule}")
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source="guarddog", rule_or_advisory=rule,
                title=hits[0].get("message") or rule, package=pkg.name, version=pkg.version,
                severity=risk_sev.get(rule, Severity.MEDIUM), confidence=Confidence.MEDIUM,
                evidence=evidence, limitations=lim))
        else:  # metadata rules return a message string or dict
            fid = make_id("mal", pkg.name, pkg.version, f"guarddog:{rule}")
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source="guarddog", rule_or_advisory=rule,
                title=f"GuardDog metadata rule: {rule}", package=pkg.name, version=pkg.version,
                severity=Severity.MEDIUM, confidence=Confidence.LOW,
                evidence=[Evidence(id=f"{fid}-e0", kind="metadata", summary=str(hits)[:500])], limitations=lim))

    if capability_ev:
        findings.append(Finding(
            id=cap_id, category=Category.MALICIOUS_INDICATOR, source="guarddog",
            rule_or_advisory="guarddog-capabilities", title="Capabilities observed by GuardDog (context only)",
            package=pkg.name, version=pkg.version, severity=Severity.INFO, confidence=Confidence.LOW,
            evidence=capability_ev[:15], limitations=lim + ["Capabilities alone are common in benign packages."]))
    return findings


def scan_packages(pkgs: list[PackageFiles]) -> tuple[list[Finding], CheckRun]:
    m = mode()
    if m == "off":
        return [], CheckRun(name="guarddog", status="not_configured",
                            detail="Install guarddog or Docker, or set GUARDDOG_MODE")
    findings, errors = [], []
    for pkg in pkgs:
        try:
            findings.extend(to_findings(run_guarddog(pkg), pkg))
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            errors.append(f"{pkg.name}@{pkg.version}: {str(exc)[:120]}")
    status = "ran" if len(errors) < len(pkgs) or not pkgs else "failed"
    detail = f"GuardDog ({m})" + (f"; errors: {'; '.join(errors[:3])}" if errors else "")
    return findings, CheckRun(name="guarddog", status=status, detail=detail, packages_checked=len(pkgs) - len(errors))
