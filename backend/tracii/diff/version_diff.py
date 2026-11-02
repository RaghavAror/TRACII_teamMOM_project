"""Temporal security diff between two releases of one package.

Highlights what a new release *introduces*: install scripts, network hosts,
sensitive capabilities, dependencies, files. A diff is a clue, not proof of
malice; findings carry LOW/MEDIUM confidence and say so.
"""

from __future__ import annotations

import difflib

from tracii.detect.static_rules import JS_EXT, OBFUSCATOR_ID_RE, OBFUSCATOR_MIN_IDS, capability_profile, scan_file
from tracii.evidence.schema import Category, Confidence, Evidence, Finding, Severity, make_id
from tracii.intake.npm_registry import PackageFiles

RISKY_CAPS = {"env_read", "sensitive_file", "exec", "dynamic_eval", "network", "encode", "system_info"}
# A capability new to one file matters even if the package used it elsewhere before.
FILE_RISKY_CAPS = {"sensitive_file", "exec", "dynamic_eval", "system_info"}
# Hijacked releases (debug 4.4.2, @react-native-aria/*) append one huge line to a normally formatted
# source file. Minified files already have long lines in the old version, so they are not counted.
READABLE_MAX_LINE = 500
INJECTED_LINE = 2000


def _added_lines(old: str | None, new: str) -> list[tuple[int, str]]:
    """(1-based line in new file, text) of lines that are new in this version."""
    if old is None:
        return list(enumerate(new.splitlines(), 1))
    out = []
    sm = difflib.SequenceMatcher(None, old.splitlines(), new_lines := new.splitlines(), autojunk=False)
    for tag, _, _, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            out.extend((j + 1, new_lines[j]) for j in range(j1, j2))
    return out


def code_changes(old: PackageFiles, new: PackageFiles) -> dict[str, dict]:
    """Per JS file that is new or modified: lines added and what the added code introduces."""
    out = {}
    for path, text in sorted(new.files.items()):
        prev = old.files.get(path)
        if not path.endswith(JS_EXT) or prev == text:
            continue
        added = _added_lines(prev, text)
        added_text = "\n".join(t for _, t in added)
        old_tags = {s.tag for s in scan_file(path, prev)} if prev is not None else set()
        new_sigs = [s for s in scan_file(path, added_text) if s.tag not in old_tags]
        longest = max(added, key=lambda x: len(x[1]), default=(0, ""))
        readable_before = prev is not None and max((len(l) for l in prev.splitlines()), default=0) < READABLE_MAX_LINE
        out[path] = {
            "status": "added" if prev is None else "modified",
            "lines_added": len(added),
            "new_capabilities": sorted({s.tag for s in new_sigs}),
            "obfuscator_ids_added": len(OBFUSCATOR_ID_RE.findall(added_text)),
            "injected_long_line": ({"line": longest[0], "length": len(longest[1])}
                                   if readable_before and len(longest[1]) > INJECTED_LINE else None),
            # first line (in the new file) where each new capability appears; signal lines index `added`
            "_lines": {s.tag: added[s.line - 1][0] for s in reversed(new_sigs) if 0 < s.line <= len(added)},
        }
    return out


def diff_packages(old: PackageFiles, new: PackageFiles) -> dict:
    a, b = capability_profile(old), capability_profile(new)
    new_caps = {t: locs for t, locs in b["capabilities"].items() if t not in a["capabilities"]}
    changed_scripts = {k: {"old": a["install_scripts"].get(k), "new": v}
                       for k, v in b["install_scripts"].items() if a["install_scripts"].get(k) != v}
    changes = code_changes(old, new)
    report = {
        "package": new.name, "old_version": old.version, "new_version": new.version,
        "install_scripts_added_or_changed": changed_scripts,
        "hosts_added": sorted(set(b["hosts"]) - set(a["hosts"])),
        "capabilities_added": new_caps,
        "dependencies_added": {k: v for k, v in b["dependencies"].items() if k not in a["dependencies"]},
        "dependencies_removed": sorted(set(a["dependencies"]) - set(b["dependencies"])),
        "files_added": sorted(set(b["files"]) - set(a["files"])),
        "files_removed": sorted(set(a["files"]) - set(b["files"])),
        "files_modified": sorted(p for p in set(old.files) & set(new.files) if old.files[p] != new.files[p]),
        "code_changes": {p: {k: v for k, v in c.items() if not k.startswith("_")} for p, c in changes.items()},
    }
    report["findings"] = [f.model_dump(mode="json") for f in diff_findings(report, changes)]
    report["security_relevant"] = bool(report["findings"])
    report["note"] = "A version diff is a clue for investigation, not proof that a change is malicious."
    return report


def diff_findings(report: dict, changes: dict[str, dict] | None = None) -> list[Finding]:
    name, ver = report["package"], report["new_version"]
    label = f"{report['old_version']} -> {ver}"
    out: list[Finding] = []
    lim = ["Version diff compares static capability patterns only; behaviour was not executed."]

    # Code injected into files that already existed: the usual shape of a hijacked release.
    injected = {p: c for p, c in (changes or {}).items()
                if c["status"] == "modified" and (c["injected_long_line"] or c["obfuscator_ids_added"] >= OBFUSCATOR_MIN_IDS
                                                  or set(c["new_capabilities"]) & FILE_RISKY_CAPS)}
    if injected:
        fid = make_id("diff", name, ver, "DIFF-CODE-INJECTED")
        evidence = []
        strong = False
        for p, c in list(injected.items())[:5]:
            if c["injected_long_line"]:
                strong = True
                evidence.append(Evidence(id=f"{fid}-e{len(evidence)}", kind="diff", file=p,
                                         line=c["injected_long_line"]["line"],
                                         summary=f"{c['injected_long_line']['length']}-character line added to a "
                                                 f"normally formatted file"))
            if c["obfuscator_ids_added"] >= OBFUSCATOR_MIN_IDS:
                strong = True
                evidence.append(Evidence(id=f"{fid}-e{len(evidence)}", kind="diff", file=p,
                                         summary=f"{c['obfuscator_ids_added']} obfuscator-style identifiers (_0x…) added"))
            for tag in sorted(set(c["new_capabilities"]) & FILE_RISKY_CAPS):
                evidence.append(Evidence(id=f"{fid}-e{len(evidence)}", kind="diff", file=p, line=c["_lines"].get(tag),
                                         summary=f"new in this file: {tag}"))
        out.append(Finding(
            id=fid, category=Category.VERSION_DIFF, source="tracii-diff", rule_or_advisory="DIFF-CODE-INJECTED",
            title=f"Suspicious code added to existing files in {label}: " + ", ".join(list(injected)[:3]),
            package=name, version=ver, severity=Severity.HIGH if strong else Severity.MEDIUM,
            confidence=Confidence.MEDIUM if strong else Confidence.LOW, evidence=evidence,
            limitations=lim + ["Compares the added lines of each file with that file's previous version."]))

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
