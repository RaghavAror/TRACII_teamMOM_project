"""Temporal security diff between two releases of one package.

Highlights what a new release *introduces*: install scripts, network hosts,
sensitive capabilities, dependencies, files. A diff is a clue, not proof of
malice; findings carry LOW/MEDIUM confidence and say so.
"""

from __future__ import annotations

from tracii.detect.static_rules import capability_profile
from tracii.evidence.schema import Category, Confidence, Evidence, Finding, Severity, make_id
from tracii.intake.npm_registry import PackageFiles

RISKY_CAPS = {"env_read", "sensitive_file", "exec", "dynamic_eval", "network", "encode", "system_info"}


def diff_packages(old: PackageFiles, new: PackageFiles) -> dict:
    a, b = capability_profile(old), capability_profile(new)
    new_caps = {t: locs for t, locs in b["capabilities"].items() if t not in a["capabilities"]}
    changed_scripts = {k: {"old": a["install_scripts"].get(k), "new": v}
                       for k, v in b["install_scripts"].items() if a["install_scripts"].get(k) != v}
    report = {
        "package": new.name, "old_version": old.version, "new_version": new.version,
        "install_scripts_added_or_changed": changed_scripts,
        "hosts_added": sorted(set(b["hosts"]) - set(a["hosts"])),
        "capabilities_added": new_caps,
        "dependencies_added": {k: v for k, v in b["dependencies"].items() if k not in a["dependencies"]},
        "dependencies_removed": sorted(set(a["dependencies"]) - set(b["dependencies"])),
        "files_added": sorted(set(b["files"]) - set(a["files"])),
        "files_removed": sorted(set(a["files"]) - set(b["files"])),
    }
    report["findings"] = [f.model_dump(mode="json") for f in diff_findings(report)]
    report["note"] = "A version diff is a clue for investigation, not proof that a change is malicious."
    return report


def diff_findings(report: dict) -> list[Finding]:
    name, ver = report["package"], report["new_version"]
    label = f"{report['old_version']} -> {ver}"
    out: list[Finding] = []
    lim = ["Version diff compares static capability patterns only; behaviour was not executed."]

    if report["install_scripts_added_or_changed"]:
        fid = make_id("diff", name, ver, "DIFF-INSTALL-SCRIPT")
        out.append(Finding(
            id=fid, category=Category.VERSION_DIFF, source="tracii-diff", rule_or_advisory="DIFF-INSTALL-SCRIPT",
            title=f"Install script added or changed in {label}", package=name, version=ver,
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            evidence=[Evidence(id=f"{fid}-e{i}", kind="diff", summary=f"scripts.{k}: {v['old']!r} -> {v['new']!r}",
                               file="package.json", snippet=v["new"])
                      for i, (k, v) in enumerate(report["install_scripts_added_or_changed"].items())],
            limitations=lim))
    risky = {t: l for t, l in report["capabilities_added"].items() if t in RISKY_CAPS}
    if risky or report["hosts_added"]:
        fid = make_id("diff", name, ver, "DIFF-NEW-CAPABILITY")
        evidence = []
        for tag, locs in risky.items():
            for loc in locs[:3]:
                file, _, line = loc.rpartition(":")
                evidence.append(Evidence(id=f"{fid}-e{len(evidence)}", kind="diff", summary=f"new capability: {tag}",
                                         file=file, line=int(line)))
        evidence += [Evidence(id=f"{fid}-h{i}", kind="diff", summary=f"new hard-coded host: {h}")
                     for i, h in enumerate(report["hosts_added"])]
        sev = Severity.HIGH if {"exec", "dynamic_eval", "sensitive_file"} & set(risky) else Severity.MEDIUM
        out.append(Finding(
            id=fid, category=Category.VERSION_DIFF, source="tracii-diff", rule_or_advisory="DIFF-NEW-CAPABILITY",
            title=f"New sensitive capabilities or hosts introduced in {label}", package=name, version=ver,
            severity=sev, confidence=Confidence.LOW, evidence=evidence, limitations=lim))
    if report["dependencies_added"]:
        fid = make_id("diff", name, ver, "DIFF-NEW-DEPENDENCY")
        out.append(Finding(
            id=fid, category=Category.VERSION_DIFF, source="tracii-diff", rule_or_advisory="DIFF-NEW-DEPENDENCY",
            title=f"New dependencies added in {label}", package=name, version=ver,
            severity=Severity.LOW, confidence=Confidence.LOW,
            evidence=[Evidence(id=f"{fid}-e{i}", kind="diff", summary=f"added dependency {k}@{v}", file="package.json")
                      for i, (k, v) in enumerate(report["dependencies_added"].items())],
            limitations=lim + ["The event-stream incident hid its payload in a newly added dependency; scan it too."]))
    return out
