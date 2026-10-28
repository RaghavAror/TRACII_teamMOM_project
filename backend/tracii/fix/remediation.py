"""Fix simulator + verified rescan.

1. propose_fix: build a package.json change (bump a direct dep, or an npm
   `overrides` entry for a transitive one) and show it as a diff. Nothing is
   applied to the user's repository.
2. resolve_lockfile: regenerate package-lock.json with
   `npm install --package-lock-only --ignore-scripts` (metadata resolution only;
   no tarballs are unpacked and no lifecycle scripts run), optionally in Docker.
3. compare: rescan the new inventory and report which findings disappeared,
   which remain and which are new. Without a successful resolve, status is
   UNVERIFIED and no improvement is claimed.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

from tracii.evidence.schema import Category, Finding, Inventory, RemediationStatus

NODE_IMAGE = os.environ.get("NPM_RESOLVER_IMAGE", "node:22-slim")


class FixProposal(BaseModel):
    finding_id: str
    kind: str                     # bump_direct | override_transitive | manual_review
    package: str
    from_version: str
    to_version: str | None
    reason: str
    caveats: list[str] = Field(default_factory=list)
    new_package_json: str | None = None
    diff: str = ""


def _semver_key(v: str) -> tuple:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", v)
    if not m:
        return (0, 0, 0, 0, v)
    major, minor, patch, pre = m.groups()
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


def pick_fixed_version(installed: str, fixed: list[str]) -> str | None:
    newer = [f for f in fixed if _semver_key(f) > _semver_key(installed)]
    if not newer:
        return None
    # prefer the smallest fix in the same major line, else the smallest overall
    same_major = [f for f in newer if _semver_key(f)[0] == _semver_key(installed)[0]]
    return min(same_major or newer, key=_semver_key)


def propose_fix(finding: Finding, inventory: Inventory, package_json: str,
                all_findings: list[Finding] | None = None) -> FixProposal:
    """Propose one change for `finding`. When `all_findings` is given, the target
    version also clears every other advisory on the same package@version."""
    manifest = json.loads(package_json)
    base = dict(finding_id=finding.id, package=finding.package, from_version=finding.version)

    if finding.category != Category.VULNERABILITY:
        return FixProposal(**base, kind="manual_review", to_version=None,
                           reason="Malicious-behaviour indicators have no 'fixed version'. Review the evidence; "
                                  "if confirmed, remove or replace the package, or pin to a release whose "
                                  "version diff does not introduce the behaviour.",
                           caveats=["Tracii does not auto-select a replacement for suspected malware."])
    target = pick_fixed_version(finding.version, finding.fixed_versions)
    if not target:
        return FixProposal(**base, kind="manual_review", to_version=None,
                           reason="The advisory lists no fixed version newer than the installed one.",
                           caveats=["Consider removing the dependency or applying a documented mitigation."])

    caveats = []
    siblings = [f for f in all_findings or [] if f.category == Category.VULNERABILITY
                and f.package == finding.package and f.version == finding.version and f.id != finding.id]
    unresolved = []
    for s in siblings:
        t = pick_fixed_version(finding.version, s.fixed_versions)
        if t is None:
            unresolved.append(s.rule_or_advisory)
        elif _semver_key(t) > _semver_key(target):
            target = t
    if siblings:
        caveats.append(f"Target chosen to also address {len(siblings) - len(unresolved)} other advisories "
                       f"on {finding.package}@{finding.version}.")
    if unresolved:
        caveats.append(f"No fixed version known for: {', '.join(unresolved)}.")
    if _semver_key(target)[0] != _semver_key(finding.version)[0]:
        caveats.append(f"Major version change {finding.version} -> {target}: expect breaking API changes; run your tests.")
    section = next((s for s in ("dependencies", "devDependencies", "optionalDependencies")
                    if finding.package in (manifest.get(s) or {})), None)
    if section:
        old_spec = manifest[section][finding.package]
        prefix = old_spec[0] if old_spec[:1] in ("^", "~") else ""
        manifest[section][finding.package] = f"{prefix}{target}"
        kind, reason = "bump_direct", f"Direct dependency: change {section}.{finding.package} from {old_spec!r} to {prefix}{target!r}."
    else:
        parents = sorted({p.direct_dependency for p in finding.paths})
        manifest.setdefault("overrides", {})[finding.package] = target
        kind = "override_transitive"
        reason = (f"Transitive dependency (via {', '.join(parents) or 'unknown parent'}): add an npm override "
                  f"forcing {finding.package}@{target}. A cleaner fix is upgrading the parent if a release depends on a fixed version.")
        caveats.append("npm overrides force the version for every parent; a parent may not support it.")
        caveats.append("Requires npm >= 8.3.")

    new_text = json.dumps(manifest, indent=2) + "\n"
    diff = "".join(difflib.unified_diff(package_json.splitlines(True), new_text.splitlines(True),
                                        "package.json (current)", "package.json (proposed)"))
    return FixProposal(**base, kind=kind, to_version=target, reason=reason, caveats=caveats,
                       new_package_json=new_text, diff=diff)


def resolver_mode() -> str:
    m = os.environ.get("NPM_RESOLVER", "auto")
    if m != "auto":
        return m
    if shutil.which("npm"):
        return "local"
    if shutil.which("docker"):
        return "docker"
    return "off"


def resolve_lockfile(package_json: str, old_lockfile: bytes | None, timeout: int = 240) -> bytes:
    """Return a regenerated package-lock.json. Raises RuntimeError if resolution cannot run."""
    mode = resolver_mode()
    if mode == "off":
        raise RuntimeError("no npm resolver available (install npm or Docker, or set NPM_RESOLVER)")
    with tempfile.TemporaryDirectory(prefix="tracii-fix-") as tmp:
        work = Path(tmp)
        (work / "package.json").write_text(package_json)
        if old_lockfile:
            (work / "package-lock.json").write_bytes(old_lockfile)
        npm_args = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
        if mode == "docker":
            cmd = ["docker", "run", "--rm", "-v", f"{work}:/w", "-w", "/w", NODE_IMAGE, *npm_args]
        else:
            cmd = npm_args
        env = {**os.environ, "npm_config_ignore_scripts": "true"}
        proc = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=timeout, env=env)
        if proc.returncode != 0:
            raise RuntimeError(f"npm resolve failed: {proc.stderr[-400:]}")
        return (work / "package-lock.json").read_bytes()


def compare(before: list[Finding], after: list[Finding],
            deep_before: set[str] | None = None) -> dict:
    """`deep_before` = package names deep-scanned originally. Malware findings on
    packages that were not deep-scanned before are coverage changes, not regressions."""
    a = {f.key: f for f in before}
    b = {f.key: f for f in after}
    new, coverage = [], []
    for k in b.keys() - a.keys():
        f = b[k]
        if (deep_before is not None and f.category != Category.VULNERABILITY
                and f.package not in deep_before):
            coverage.append(f.model_dump(mode="json"))
        else:
            new.append(f.model_dump(mode="json"))
    return {
        "fixed": [a[k].model_dump(mode="json") for k in a.keys() - b.keys()],
        "remaining": [b[k].model_dump(mode="json") for k in a.keys() & b.keys()],
        "new": new,
        "newly_covered": coverage,
    }


def target_status(proposal: FixProposal, comparison: dict | None) -> RemediationStatus:
    if comparison is None:
        return RemediationStatus.UNVERIFIED
    fixed_ids = {f["id"] for f in comparison["fixed"]}
    return RemediationStatus.VERIFIED_FIXED if proposal.finding_id in fixed_ids else RemediationStatus.STILL_PRESENT
