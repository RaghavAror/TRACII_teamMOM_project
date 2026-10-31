"""CI gate: decide pass/fail for a finished scan.

- `enforce` fails the build on findings at or above `fail_on`; `observe` only reports
  what would have failed (Veracode's enforcement/observer split).
- Unknown severity is never silently promoted or ignored: it is counted and listed,
  and gates only with `fail_on_unknown`.
- A scan whose required checks failed is INCOMPLETE, not a pass: no findings from a
  check that did not run is not evidence of safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from tracii.evidence.schema import Category, Finding, ScanResult, Severity

RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
THRESHOLDS = ("critical", "high", "medium", "low", "none")
REQUIRED_CHECKS = ("inventory", "osv")

Outcome = Literal["pass", "fail", "incomplete"]


@dataclass
class GatePolicy:
    fail_on: str = "high"                     # critical | high | medium | low | none
    mode: Literal["enforce", "observe"] = "enforce"
    categories: tuple[str, ...] = (Category.VULNERABILITY.value, Category.MALICIOUS_INDICATOR.value,
                                   Category.VERSION_DIFF.value)
    fail_on_unknown: bool = False
    allow_incomplete: bool = False
    include_dev: bool = True                  # False: ignore findings reached only via devDependencies


@dataclass
class GateResult:
    outcome: Outcome
    exit_code: int
    blocking: list[Finding] = field(default_factory=list)
    unknown: list[Finding] = field(default_factory=list)
    ignored_dev: int = 0
    failed_checks: list[str] = field(default_factory=list)
    policy: GatePolicy = field(default_factory=GatePolicy)

    @property
    def would_fail(self) -> bool:
        return bool(self.blocking) or (bool(self.failed_checks) and not self.policy.allow_incomplete)


def _dev_only(f: Finding) -> bool:
    return bool(f.paths) and all(p.dev_only for p in f.paths)


def evaluate(result: ScanResult, policy: GatePolicy) -> GateResult:
    if policy.fail_on not in THRESHOLDS:
        raise ValueError(f"fail_on must be one of {THRESHOLDS}")
    floor = None if policy.fail_on == "none" else RANK[Severity(policy.fail_on)]
    blocking, unknown, ignored_dev = [], [], 0
    for f in result.findings:
        if f.category.value not in policy.categories:
            continue
        if not policy.include_dev and _dev_only(f):
            ignored_dev += 1
            continue
        if f.severity is Severity.UNKNOWN:
            unknown.append(f)
            if policy.fail_on_unknown and floor is not None:
                blocking.append(f)
        elif floor is not None and RANK[f.severity] >= floor:
            blocking.append(f)

    failed = [c.name for c in result.checks if c.name in REQUIRED_CHECKS and c.status != "ran"]
    gr = GateResult(outcome="pass", exit_code=0, blocking=blocking, unknown=unknown, ignored_dev=ignored_dev,
                    failed_checks=failed, policy=policy)
    if failed and not policy.allow_incomplete:
        gr.outcome = "incomplete"
    elif blocking:
        gr.outcome = "fail"
    if policy.mode == "enforce":
        gr.exit_code = {"pass": 0, "fail": 1, "incomplete": 2}[gr.outcome]
    return gr


def _severity_counts(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    order = [s.value for s in Severity]
    return ", ".join(f"{counts[s]} {s}" for s in order if s in counts) or "none"


def markdown_summary(result: ScanResult, gate: GateResult, max_rows: int = 25) -> str:
    """Report for $GITHUB_STEP_SUMMARY or a PR comment. Package text is escaped, never rendered as markup."""
    def esc(s: str) -> str:
        return s.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")

    icon = {"pass": "✅", "fail": "❌", "incomplete": "⚠️"}[gate.outcome]
    note = ""
    if gate.failed_checks and gate.outcome == "pass":
        icon, note = "⚠️", " (incomplete scan allowed)"
    if gate.policy.mode == "observe" and gate.would_fail:
        note += " (observe mode: not blocking)"
    out = [f"## {icon} Tracii supply-chain gate: **{gate.outcome.upper()}**{note}", "",
           f"Project `{esc(result.inventory.project_name)}` · {len(result.inventory.packages)} packages · "
           f"threshold `{gate.policy.fail_on}` · categories `{', '.join(gate.policy.categories)}`", ""]
    by_cat: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category.value, []).append(f)
    out += ["| Category | Findings |", "|---|---|"]
    out += [f"| {c} | {_severity_counts(fs)} |" for c, fs in sorted(by_cat.items())] or ["| – | none detected |"]
    out.append("")
    if gate.failed_checks:
        out.append(f"**Required checks did not run:** {', '.join(gate.failed_checks)}. "
                   "No findings from a check that did not run is not a pass.")
        out.append("")
    if gate.blocking:
        out += [f"### Blocking findings ({len(gate.blocking)})", "",
                "| Severity | Package | Finding | Fixed in | Path |", "|---|---|---|---|---|"]
        for f in sorted(gate.blocking, key=lambda f: -RANK.get(f.severity, -1))[:max_rows]:
            path = (" › ".join(f.paths[0].nodes) + (" (dev only)" if _dev_only(f) else "")) if f.paths else ""
            out.append(f"| {f.severity.value} | `{esc(f.package)}@{esc(f.version)}` | "
                       f"{esc(f.rule_or_advisory)}: {esc(f.title)[:120]} | {esc(', '.join(f.fixed_versions[:3]))} | "
                       f"{esc(path)} |")
        if len(gate.blocking) > max_rows:
            out.append(f"\n…and {len(gate.blocking) - max_rows} more (see the SARIF report).")
        out.append("")
    if gate.unknown and not gate.policy.fail_on_unknown:
        out.append(f"{len(gate.unknown)} finding(s) have unknown severity and were not gated "
                   "(use `--fail-on-unknown` to gate them).")
    if gate.ignored_dev:
        out.append(f"{gate.ignored_dev} finding(s) reached only through devDependencies were ignored.")
    checks = ", ".join(f"{c.name}: {c.status}" for c in result.checks)
    out += ["", f"<sub>Checks: {esc(checks)}. Results say what these checks detected; "
                "no finding is not a guarantee of safety.</sub>"]
    return "\n".join(out) + "\n"
