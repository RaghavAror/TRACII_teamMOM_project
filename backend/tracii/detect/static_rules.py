"""Tracii static behaviour rules + evidence-backed attack-chain correlation.

Reads package text only (never executes it). Single capabilities such as
"uses https" are common in benign code, so they are NOT reported alone.
Findings are raised when:
- a lifecycle install script exists (info; context for everything else),
- an install-time entry file performs network/process activity,
- one file shows a source -> transform -> sink chain (e.g. env -> base64 -> https),
- dynamic code execution is fed by a large encoded blob (obfuscation).
Each chain step links to its own Evidence item with file and line.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from tracii.evidence.schema import Category, Confidence, Evidence, Finding, Severity, make_id
from tracii.intake.npm_registry import PackageFiles

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# tag -> (role in a chain, patterns)
CAPABILITIES: dict[str, tuple[str, list[str]]] = {
    "env_read": ("source", [r"process\.env\b"]),
    "sensitive_file": ("source", [r"\.npmrc", r"\.ssh[/\\]", r"id_rsa", r"\.aws[/\\]credentials",
                                  r"\.bash_history", r"/etc/passwd", r"wallet\.dat"]),
    "system_info": ("source", [r"os\.(hostname|userInfo|networkInterfaces)\s*\("]),
    "encode": ("transform", [r"toString\(\s*['\"](base64|hex)['\"]\s*\)", r"\bbtoa\s*\(",
                             r"Buffer\.from\([^)]*\)\.toString", r"createCipheriv"]),
    "network": ("sink", [r"\bhttps?\.(request|get)\s*\(", r"\bfetch\s*\(", r"\bnet\.(connect|createConnection)\s*\(",
                         r"\bdns\.(lookup|resolve\w*)\s*\(", r"require\(\s*['\"](axios|node-fetch|request)['\"]\s*\)",
                         r"new\s+WebSocket\s*\("]),
    "exec": ("sink", [r"require\(\s*['\"]child_process['\"]\s*\)", r"\bexecSync\s*\(", r"\bspawn(Sync)?\s*\(",
                      r"\bexec\s*\(\s*['\"`]"]),
    "dynamic_eval": ("transform", [r"\beval\s*\(", r"\bnew\s+Function\s*\(", r"\bFunction\s*\(\s*['\"]"]),
}
_COMPILED = {tag: (role, [re.compile(p) for p in pats]) for tag, (role, pats) in CAPABILITIES.items()}
HOST_RE = re.compile(r"""https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?""")
# request option objects: { hostname: 'x.y', host: "x.y" }
HOST_OPT_RE = re.compile(r"""\b(?:hostname|host)\s*:\s*['"`]([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})['"`]""")
LONG_BLOB_RE = re.compile(r"""['"`]([A-Za-z0-9+/=]{400,}|(?:\\x[0-9a-fA-F]{2}){100,})['"`]""")
JS_EXT = (".js", ".cjs", ".mjs", ".ts")


@dataclass
class Signal:
    tag: str
    role: str
    file: str
    line: int
    text: str


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def scan_file(path: str, text: str) -> list[Signal]:
    signals = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for tag, (role, pats) in _COMPILED.items():
            if any(p.search(line) for p in pats):
                signals.append(Signal(tag, role, path, lineno, line.strip()[:300]))
    return signals


def hosts_in(text: str) -> set[str]:
    return {m.group(1).lower() for rx in (HOST_RE, HOST_OPT_RE) for m in rx.finditer(text)}


def install_scripts(manifest: dict) -> dict[str, str]:
    scripts = manifest.get("scripts") or {}
    return {k: str(v) for k, v in scripts.items() if k in INSTALL_HOOKS}


def _script_entry_files(cmd: str, files: dict[str, str]) -> list[str]:
    """Files an install command runs, e.g. 'node setup.js && node lib/x.js'."""
    out = []
    for tok in re.split(r"[\s;&|]+", cmd):
        tok = tok.strip("'\"").removeprefix("./")
        if tok in files:
            out.append(tok)
    return out


def _ev(fid: str, n: int, s: Signal, kind: str = "code") -> Evidence:
    return Evidence(id=f"{fid}-e{n}", kind=kind, summary=f"{s.role}: {s.tag}", file=s.file, line=s.line, snippet=s.text)


def analyze_package(pkg: PackageFiles, source: str = "tracii-static") -> list[Finding]:
    findings: list[Finding] = []
    name, version = pkg.name, pkg.version
    scripts = install_scripts(pkg.manifest)
    limitations = ["Static pattern analysis of package text; nothing was executed.",
                   "Minified, bundled or dynamically built code can hide behaviour from these rules."]
    if pkg.skipped:
        limitations.append(f"{len(pkg.skipped)} binary/oversized files were not analysed.")

    install_files: set[str] = set()
    if scripts:
        fid = make_id("mal", name, version, "TRACII-INSTALL-SCRIPT")
        findings.append(Finding(
            id=fid, category=Category.MALICIOUS_INDICATOR, source=source,
            rule_or_advisory="TRACII-INSTALL-SCRIPT", title="Package runs a lifecycle script at install time",
            package=name, version=version, severity=Severity.INFO, confidence=Confidence.LOW,
            evidence=[Evidence(id=f"{fid}-e{i}", kind="install_script", summary=f"scripts.{hook}",
                               file="package.json", snippet=cmd) for i, (hook, cmd) in enumerate(scripts.items())],
            limitations=limitations + ["Many legitimate packages (native builds) use install scripts."],
        ))
        for cmd in scripts.values():
            install_files.update(_script_entry_files(cmd, pkg.files))

    for path, text in sorted(pkg.files.items()):
        if not path.endswith(JS_EXT):
            continue
        signals = scan_file(path, text)
        tags = {s.tag for s in signals}
        roles = {s.role for s in signals}

        # 1. source -> transform -> sink chain in one file. env + network alone is
        # how every API client works, so require an encode step, a sensitive
        # file read, or install-time execution before calling it a chain.
        corroborated = "encode" in tags or "sensitive_file" in tags or path in install_files
        if {"source", "sink"} <= roles and corroborated:
            src = next(s for s in signals if s.role == "source")
            trf = next((s for s in signals if s.tag == "encode"), None)
            snk = next(s for s in signals if s.role == "sink")
            steps = [s for s in (src, trf, snk) if s]
            fid = make_id("mal", name, version, "TRACII-CHAIN-EXFIL", path)
            at_install = path in install_files
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source=source,
                rule_or_advisory="TRACII-CHAIN-EXFIL",
                title=f"Possible data-exfiltration chain in {path}: " + " -> ".join(s.tag for s in steps)
                      + (" (runs at install time)" if at_install else ""),
                package=name, version=version,
                severity=Severity.HIGH if at_install or trf else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=[_ev(fid, i, s) for i, s in enumerate(steps)]
                         + [Evidence(id=f"{fid}-h{i}", kind="code", summary=f"hard-coded host {h}", file=path)
                            for i, h in enumerate(sorted(hosts_in(text)))],
                limitations=limitations + ["Steps are correlated within one file by pattern, not by full data-flow (taint) analysis."],
            ))
        # 2. install-time entry performing network/process activity
        elif path in install_files and tags & {"network", "exec"}:
            fid = make_id("mal", name, version, "TRACII-INSTALL-NET-EXEC", path)
            hits = [s for s in signals if s.tag in ("network", "exec")][:5]
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source=source,
                rule_or_advisory="TRACII-INSTALL-NET-EXEC",
                title=f"Install script entry {path} uses network or child processes",
                package=name, version=version, severity=Severity.MEDIUM, confidence=Confidence.LOW,
                evidence=[_ev(fid, i, s) for i, s in enumerate(hits)],
                limitations=limitations + ["Native build tools (node-gyp, prebuild) legitimately download binaries."],
            ))

        # 3. obfuscated payload fed to dynamic evaluation
        if "dynamic_eval" in tags:
            for m in LONG_BLOB_RE.finditer(text):
                if entropy(m.group(1)) > 4.0:
                    line = text.count("\n", 0, m.start()) + 1
                    fid = make_id("mal", name, version, "TRACII-OBFUSCATED-EVAL", path)
                    ev_sig = next(s for s in signals if s.tag == "dynamic_eval")
                    findings.append(Finding(
                        id=fid, category=Category.MALICIOUS_INDICATOR, source=source,
                        rule_or_advisory="TRACII-OBFUSCATED-EVAL",
                        title=f"Encoded high-entropy blob with dynamic evaluation in {path}",
                        package=name, version=version, severity=Severity.MEDIUM, confidence=Confidence.LOW,
                        evidence=[_ev(fid, 0, ev_sig),
                                  Evidence(id=f"{fid}-e1", kind="code", summary="encoded blob",
                                           file=path, line=line, snippet=m.group(1)[:120] + "...")],
                        limitations=limitations,
                    ))
                    break
    return findings


def capability_profile(pkg: PackageFiles) -> dict:
    """Summary used by the version diff: capability tags, hosts and install scripts."""
    caps: dict[str, list[str]] = {}
    hosts: set[str] = set()
    for path, text in pkg.files.items():
        if not path.endswith(JS_EXT):
            continue
        for s in scan_file(path, text):
            caps.setdefault(s.tag, []).append(f"{s.file}:{s.line}")
        hosts |= hosts_in(text)
    return {"capabilities": caps, "hosts": sorted(hosts), "install_scripts": install_scripts(pkg.manifest),
            "dependencies": dict(pkg.manifest.get("dependencies") or {}), "files": sorted(pkg.files)}
