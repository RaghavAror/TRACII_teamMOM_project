"""PDF security assessment report, built from the structured scan result (never a screenshot).

Rules it keeps, same as the UI:
- known vulnerabilities, known malware (OSV MAL-) and suspicious behaviour are reported separately;
- checks that did not run are listed as not run, never as passed;
- AI text appears only if a model call actually succeeded for this scan, labelled as an assessment;
- nothing is filled in that the scan did not record.
Package-derived text is untrusted: it is escaped before it reaches ReportLab's markup parser.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from tracii.evidence.schema import Category, Finding, ScanResult
from tracii.gate import GateResult

SEV = ["critical", "high", "medium", "low", "info", "unknown"]
SEV_COLOR = {"critical": "#9b1c1c", "high": "#d92d20", "medium": "#c27803", "low": "#2e78c7",
             "info": "#7d8796", "unknown": "#7d8796"}
INK, MUTED, LINE, SOFT = colors.HexColor("#0b1220"), colors.HexColor("#5b6577"), colors.HexColor("#e3e8f0"), colors.HexColor("#f4f6fb")
ACCENT, ACCENT2 = colors.HexColor("#0866ff"), colors.HexColor("#7c3aed")
SOURCE_LABEL = {"osv-api": "OSV.dev API", "osv-scanner": "OSV-Scanner", "guarddog": "GuardDog (DataDog)",
                "tracii-static": "TRACII behaviour rules"}
MAX_DETAILED = 60            # detailed write-ups; every finding is still listed in the appendix table
_TRANSLATE = str.maketrans({"→": "->", "←": "<-", "—": "-", "–": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
                            "…": "...", "≥": ">=", "≤": "<=", "•": "-", "·": "-", "✓": "v", "×": "x"})


def _plain(value: object, limit: int | None = None) -> str:
    """Untrusted text -> Latin-1 (the base PDF fonts), for canvas drawing."""
    s = str(value if value is not None else "")
    if limit and len(s) > limit:
        s = s[:limit].rstrip() + " ..."
    return s.translate(_TRANSLATE).encode("latin-1", "replace").decode("latin-1")


def _t(value: object, limit: int | None = None) -> str:
    """Untrusted text -> safe for Paragraph markup and the Latin-1 base fonts."""
    return escape(_plain(value, limit))


def is_known_malware(f: Finding) -> bool:
    return f.category == Category.MALICIOUS_INDICATOR and f.rule_or_advisory.startswith("MAL-")


def _dev_only(f: Finding) -> bool:
    return bool(f.paths) and all(p.dev_only for p in f.paths)


def _direct(f: Finding) -> bool:
    return any(len(p.nodes) == 2 for p in f.paths)


def priority_key(f: Finding) -> tuple:
    """Same order as the UI: known malware, severity, production path, direct, fix available."""
    return (0 if is_known_malware(f) else 1, SEV.index(f.severity.value), 1 if _dev_only(f) else 0,
            0 if _direct(f) else 1, 0 if f.fixed_versions else 1)


def type_label(f: Finding) -> str:
    if f.category == Category.VULNERABILITY:
        return "Known vulnerability (advisory)"
    if is_known_malware(f):
        return "Known malicious package (OSV MAL- record)"
    if f.category == Category.MALICIOUS_INDICATOR:
        return "Suspicious behaviour (heuristic indicator, not confirmed malware)"
    return f.category.value.replace("_", " ").capitalize()


def recommended_action(f: Finding) -> str:
    via = ", ".join(sorted({p.direct_dependency for p in f.paths}))
    if is_known_malware(f):
        return ("Remove this version from the dependency tree" + (f" (it arrives via {via})" if via else "") +
                ". Only replace it with a version outside the affected range in the OSV record, and treat secrets "
                "on machines that installed it as exposed.")
    if f.category == Category.VULNERABILITY:
        if not f.fixed_versions:
            return ("No fixed version is published. Check whether the app uses the affected functionality, "
                    "consider replacing the package, and watch the advisory.")
        if _direct(f):
            return f"Upgrade {f.package} to {' or '.join(f.fixed_versions)} in package.json, then rescan to verify."
        return (f"Upgrade the parent ({via or 'unknown'}) to a release that depends on {f.package} >= "
                f"{f.fixed_versions[0]}, or add an npm override; then rescan to verify.")
    if f.category == Category.MALICIOUS_INDICATOR:
        if f.severity.value == "info":
            return "Context only (e.g. an install script or a capability). No action unless other findings point here."
        return ("Review the cited code before trusting this version; compare it with the previous release (version "
                "diff) and pin to a version without the behaviour if it is unexplained.")
    return "Review the cited evidence."


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=12.5,
                          textColor=INK, alignment=TA_LEFT)
    return {
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=7.8, leading=10, textColor=MUTED),
        "mono": ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=7.8, leading=10),
        "cell": ParagraphStyle("cell", parent=body, fontSize=7.8, leading=9.8),
        "h1": ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=15, leading=19, spaceBefore=4,
                             spaceAfter=8, textColor=INK, keepWithNext=1),
        "h2": ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=10.5, leading=14, spaceBefore=8,
                             spaceAfter=4, textColor=INK, keepWithNext=1),
        "h2flow": ParagraphStyle("h2flow", parent=body, fontName="Helvetica-Bold", fontSize=10.5, leading=14,
                                 spaceBefore=8, spaceAfter=4, textColor=INK),   # above long tables: may sit at a page end
        "title": ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=INK),
        "kicker": ParagraphStyle("kicker", parent=body, fontName="Helvetica-Bold", fontSize=8.5, leading=11,
                                 textColor=ACCENT),
    }


def _table(rows: list[list], widths: list[float], header: bool = True, zebra: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 7.8),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), INK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, SOFT])]
    t.setStyle(TableStyle(style))
    return t


def _sev(sev: str) -> str:
    return f'<font color="{SEV_COLOR.get(sev, "#7d8796")}"><b>{sev.upper()}</b></font>'


def build_pdf(result: ScanResult, gate_result: GateResult, ai_notes: dict[str, dict] | None = None,
              generated_at: datetime | None = None) -> bytes:
    ai_notes = ai_notes or {}
    generated_at = generated_at or datetime.now(timezone.utc)
    st = _styles()
    P = lambda text, style="body": Paragraph(text, st[style])  # noqa: E731
    inv, findings = result.inventory, result.findings
    src = result.source
    project = f"{src.label}" + (f" @ {src.ref} ({src.commit_sha[:12]})" if src.commit_sha else "")
    try:
        scanned = datetime.fromisoformat(result.created_at).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        scanned = result.created_at

    mal = [f for f in findings if is_known_malware(f)]
    vulns = [f for f in findings if f.category == Category.VULNERABILITY]
    sus = [f for f in findings if f.category == Category.MALICIOUS_INDICATOR and not is_known_malware(f)]
    posture = [f for f in findings if f.category == Category.POSTURE]
    grouped = {f.id for f in mal + vulns + sus + posture}
    other = [f for f in findings if f.id not in grouped]
    direct = sum(1 for p in inv.packages if p.direct)
    ranked = sorted((f for f in findings if f.severity.value != "info"), key=priority_key)
    width = A4[0] - 36 * mm

    def on_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        if doc.page == 1:
            canvas.setFillColor(ACCENT)
            canvas.rect(0, h - 9 * mm, w * 0.6, 9 * mm, stroke=0, fill=1)
            canvas.setFillColor(ACCENT2)
            canvas.rect(w * 0.6, h - 9 * mm, w * 0.4, 9 * mm, stroke=0, fill=1)
        else:
            canvas.setFont("Helvetica-Bold", 8)
            canvas.setFillColor(ACCENT)
            canvas.drawString(18 * mm, h - 11 * mm, "TRACII")
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(MUTED)
            canvas.drawRightString(w - 18 * mm, h - 11 * mm, _plain(f"{src.label} - scan {result.scan_id}", 90))
            canvas.setStrokeColor(LINE)
            canvas.line(18 * mm, h - 13 * mm, w - 18 * mm, h - 13 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"TRACII report - scan {result.scan_id} - generated {generated_at:%Y-%m-%d %H:%M} UTC - "
                                            "no finding is not a guarantee of safety")
        canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story: list = []

    # 1. cover / overview
    story += [Spacer(1, 22 * mm), P("TRACII - AI-NATIVE APPLICATION &amp; SOFTWARE SUPPLY-CHAIN SECURITY", "kicker"),
              Spacer(1, 4), P("Supply-chain security assessment", "title"), Spacer(1, 10)]
    story.append(_table([[P("<b>Project</b>", "cell"), P(_t(project), "cell")],
                         [P("<b>Source</b>", "cell"), P(_t(f"{src.kind}" + (f", sub-directory {src.subdir}" if src.subdir else "")), "cell")],
                         [P("<b>Scanned</b>", "cell"), P(_t(scanned), "cell")],
                         [P("<b>Scan ID</b>", "cell"), P(_t(result.scan_id), "mono")],
                         [P("<b>Report generated</b>", "cell"), P(f"{generated_at:%Y-%m-%d %H:%M:%S} UTC", "cell")],
                         [P("<b>Lockfile</b>", "cell"), P(f"package-lock.json v{inv.lockfile_version} - {_t(inv.project_name)}", "cell")]]
                        + ([[P("<b>Rescan of</b>", "cell"), P(_t(result.parent_scan_id), "mono")]] if result.parent_scan_id else []),
                        [38 * mm, width - 38 * mm], header=False))
    outcome = gate_result.outcome.upper()
    verdict = (f"{len(mal)} known malicious package(s) in the dependency tree" if mal else
               f"{len(gate_result.blocking)} blocking finding(s) at severity {gate_result.policy.fail_on} or above"
               if gate_result.outcome == "fail" else
               "No blocking findings from the checks that ran" if gate_result.outcome == "pass" else
               "Scan incomplete: a required check did not run")
    story += [Spacer(1, 10), P(f'<font color="{ "#12805c" if gate_result.outcome == "pass" else "#d92d20"}"><b>CI gate: {outcome}</b></font>'
                               f" (fail on {gate_result.policy.fail_on}, exit code {gate_result.exit_code})", "h2"),
              P(f"<b>{_t(verdict)}</b>. Deterministic scanner verdict; no AI involved."),
              PageBreak()]

    # 2. executive summary
    story.append(P("1. Executive summary", "h1"))
    story.append(P(f"TRACII analysed <b>{len(inv.packages)}</b> packages from the lockfile: <b>{direct}</b> direct and "
                   f"<b>{len(inv.packages) - direct}</b> transitive (counted per lockfile entry), "
                   f"{sum(1 for p in inv.packages if p.dev)} of them dev-only and "
                   f"{sum(1 for p in inv.packages if p.has_install_script)} with install scripts. "
                   "Finding types are kept separate and are never merged into one score."))
    story.append(Spacer(1, 6))
    head = ["Finding type"] + [s.capitalize() for s in SEV] + ["Total"]
    rows = [head]
    for label, group in (("Known malicious packages (OSV MAL-)", mal), ("Known vulnerabilities (advisories)", vulns),
                         ("Suspicious behaviour (heuristic)", sus), ("Repository posture", posture), ("Version diff", other)):
        if label == "Version diff" and not group:
            continue
        rows.append([P(label, "cell")] + [str(sum(1 for f in group if f.severity.value == s)) for s in SEV] + [str(len(group))])
    story.append(_table(rows, [58 * mm] + [(width - 58 * mm) / 7] * 7))
    if ranked:
        story += [P("Look at these first", "h2"),
                  P("Ordered by scanner facts only: known malware, severity, production path, direct dependency, fix available.", "small")]
        story.append(_table([["#", "Package", "Finding", "Why first"]] + [
            [str(i + 1), P(_t(f"{f.package}@{f.version}"), "mono"), P(_t(f.rule_or_advisory), "mono"),
             P(_t(", ".join(x for x in ["known malware" if is_known_malware(f) else f.severity.value,
                                        "dev only" if _dev_only(f) else "ships to production",
                                        "direct" if _direct(f) else "transitive",
                                        (f"fix: {f.fixed_versions[0]}" if f.fixed_versions else "no fix published")
                                        if f.category == Category.VULNERABILITY else ""] if x)), "cell")]
            for i, f in enumerate(ranked[:10])], [8 * mm, 48 * mm, 50 * mm, width - 106 * mm]))

    # 3. scan coverage
    story.append(P("2. Scan coverage", "h1"))
    story.append(P("Checks that did not run are listed as such. No findings from a check that did not run is not a pass."))
    story.append(Spacer(1, 4))
    story.append(_table([["Check", "Status", "Packages", "Detail"]] + [
        [P(f"<b>{_t(c.name)}</b>", "cell"),
         P(f'<font color="{"#12805c" if c.status == "ran" else "#c27803" if c.status in ("skipped", "not_configured") else "#d92d20"}">'
           f"<b>{_t(c.status.replace('_', ' ').upper())}</b></font>", "cell"),
         str(c.packages_checked or "-"), P(_t(c.detail, 300), "cell")] for c in result.checks],
        [34 * mm, 26 * mm, 18 * mm, width - 78 * mm]))
    story.append(P("Data sources: lockfile (inventory, licences, install-script flags); OSV.dev advisories incl. GitHub "
                   "Security Advisories and OSV MAL- known-malware records; npm registry tarballs (integrity-verified, "
                   "read in memory, never installed or run) for TRACII behaviour rules and GuardDog.", "small"))
    for w in inv.warnings:
        story.append(P(f"Inventory warning: {_t(w)}", "small"))

    # 4. detailed findings
    story += [PageBreak(), P("3. Detailed findings", "h1")]
    detailed = ranked[:MAX_DETAILED]
    if not ranked:
        story.append(P("No findings above info level from the checks that ran."))
    else:
        story.append(P(f"{len(detailed)} of {len(ranked)} findings above info level, in priority order"
                       + (f" (first {MAX_DETAILED}; every finding is listed in the appendix)" if len(ranked) > MAX_DETAILED else "")
                       + ". Info-level context findings are listed in the appendix.", "small"))
    for f in detailed:
        paths = [" -> ".join(p.nodes) + (" (dev only)" if p.dev_only else "") for p in f.paths[:3]]
        ev = [f"<b>[{_t(e.kind)}]</b> {_t(e.summary, 400)}" + (f" <font face='Courier'>{_t(e.file)}{':' + str(e.line) if e.line else ''}</font>" if e.file else "")
              + (f" <font color='#0866ff'>{_t(e.url, 120)}</font>" if e.url else "") + f" <font color='#5b6577'>(evidence {_t(e.id)})</font>"
              for e in f.evidence[:4]]
        facts = [
            [P("<b>Finding ID</b>", "cell"), P(_t(f.id), "mono"), P("<b>Severity</b>", "cell"), P(_sev(f.severity.value) + f" - confidence {f.confidence.value}", "cell")],
            [P("<b>Package</b>", "cell"), P(_t(f"{f.package}@{f.version}"), "mono"), P("<b>Reference</b>", "cell"),
             P(_t(f.rule_or_advisory + (f" ({', '.join(f.aliases)})" if f.aliases else "")), "mono")],
            [P("<b>Type</b>", "cell"), P(_t(type_label(f)), "cell"), P("<b>Source</b>", "cell"), P(_t(SOURCE_LABEL.get(f.source, f.source)), "cell")],
            [P("<b>Reaches app</b>", "cell"), P(_t(("directly" if _direct(f) else "transitively") + " via " + ", ".join(sorted({p.direct_dependency for p in f.paths}))
                                                    + (" (dev only: not shipped)" if _dev_only(f) else "")) if f.paths else "path not recorded", "cell"),
             P("<b>Fixed in</b>", "cell"), P(_t(", ".join(f.fixed_versions) or ("none published" if f.category == Category.VULNERABILITY else "n/a")), "cell")],
        ]
        block = [P(f"{_sev(f.severity.value)}&nbsp;&nbsp;<b>{_t(f.title, 160)}</b>", "h2"),
                 _table(facts, [22 * mm, width / 2 - 22 * mm, 20 * mm, width / 2 - 20 * mm], header=False, zebra=False)]
        if paths:
            block.append(P("<b>Impact path:</b> " + "<br/>".join(f"<font face='Courier'>{_t(x, 300)}</font>" for x in paths), "cell"))
        if ev:
            block.append(P("<b>Evidence:</b><br/>" + "<br/>".join(ev), "cell"))
        block.append(P(f"<b>Recommended action:</b> {_t(recommended_action(f))}", "cell"))
        if f.limitations:
            block.append(P("Limitations: " + _t(" ".join(f.limitations), 500), "small"))
        story += [KeepTogether(block[:3]), *block[3:], Spacer(1, 6)]

    # 5. dependency intelligence
    story += [PageBreak(), P("4. Dependency intelligence", "h1"),
              P("The interactive 3D dependency graph is not reproduced in this PDF; the dependency paths below come from the "
                "same graph data. Open the scan in TRACII to explore it.", "small")]
    exposed: dict[str, list[Finding]] = {}
    for f in ranked:
        for p in f.paths:
            if not p.dev_only:
                exposed.setdefault(p.direct_dependency, []).append(f)
    if exposed:
        story.append(P("Direct dependencies that bring in the most risk (production paths)", "h2"))
        rows = [["Direct dependency", "Findings via it", "Worst", "Example finding"]]
        for dep, fs in sorted(exposed.items(), key=lambda kv: (min(priority_key(f) for f in kv[1]), -len(kv[1])))[:15]:
            uniq = {f.id: f for f in fs}
            worst = min(uniq.values(), key=priority_key)
            rows.append([P(_t(dep), "mono"), str(len(uniq)), P(_sev(worst.severity.value), "cell"),
                         P(_t(f"{worst.package}@{worst.version} {worst.rule_or_advisory}"), "mono")])
        story.append(_table(rows, [50 * mm, 26 * mm, 22 * mm, width - 98 * mm]))
    story.append(P("Important dependency paths (highest-priority findings)", "h2"))
    seen, rows = set(), [["Finding", "Path to the application"]]
    for f in ranked:
        for p in f.paths[:1]:
            key = tuple(p.nodes)
            if key in seen:
                continue
            seen.add(key)
            rows.append([P(_t(f"{f.package}@{f.version}") + "<br/>" + _sev(f.severity.value), "mono"),
                         P(_t(" -> ".join(p.nodes) + (" (dev only)" if p.dev_only else ""), 400), "mono")])
        if len(rows) > 15:
            break
    story.append(_table(rows, [45 * mm, width - 45 * mm]) if len(rows) > 1 else P("No dependency paths to report."))

    # 6. AI investigation
    story += [P("5. AI investigation", "h1"),
              P("AI assessments explain the scanner's evidence. They are not findings, every claim must cite an evidence ID "
                "(uncited claims are discarded), and they never change the deterministic scanner verdict.", "small")]
    by_id = {f.id: f for f in findings}
    ai_rows = [(by_id[fid], note) for fid, note in ai_notes.items() if fid in by_id]
    if not ai_rows:
        story.append(P("No AI investigation was run for this scan, so this report contains no AI content."))
    for f, note in ai_rows:
        story.append(P(f"{_t(f.package)}@{_t(f.version)} - {_t(f.rule_or_advisory)} (finding {_t(f.id)})", "h2"))
        if ex := note.get("explain"):
            story.append(P(f"<b>AI assessment ({_t(ex.get('model'))}):</b> {_t(ex.get('assessment'))}, confidence "
                           f"{_t(ex.get('confidence'))}. Scanner verdict unchanged: {_t(ex.get('scanner_category'))} / "
                           f"{_t(ex.get('scanner_severity'))}.", "cell"))
            if ex.get("observed"):
                story.append(P(f"<b>Observed:</b> {_t(ex['observed'], 600)}", "cell"))
            for c in (ex.get("claims") or [])[:6]:
                story.append(P(f"- {_t(c.get('text'), 400)} <font color='#5b6577'>[evidence {_t(', '.join(c.get('evidence_ids') or []))}]</font>", "cell"))
            if ex.get("next_action"):
                story.append(P(f"<b>AI-suggested next action:</b> {_t(ex['next_action'], 500)}", "cell"))
        if ag := note.get("agents"):
            j = ag.get("judge") or {}
            story.append(P(f"<b>Multi-agent judge ({_t(j.get('model'))}):</b> priority {_t(j.get('priority'))}. {_t(j.get('verdict'), 600)}", "cell"))
            for c in (j.get("claims") or [])[:4]:
                story.append(P(f"- {_t(c.get('text'), 400)} <font color='#5b6577'>[evidence {_t(', '.join(c.get('evidence_ids') or []))}]</font>", "cell"))
        story.append(Spacer(1, 4))

    # 7. CI gate
    pol = gate_result.policy
    story += [P("6. CI security gate", "h1"),
              _table([[P("<b>Result</b>", "cell"), P(f"<b>{outcome}</b> (exit code {gate_result.exit_code}, mode {pol.mode})", "cell")],
                      [P("<b>Threshold</b>", "cell"), P(f"fail on {pol.fail_on}" + (" - unknown severity gated" if pol.fail_on_unknown else "")
                                                        + (" - dev-only findings ignored" if not pol.include_dev else ""), "cell")],
                      [P("<b>Gated categories</b>", "cell"), P(_t(", ".join(pol.categories)) + " (repository posture never fails the build)", "cell")],
                      [P("<b>Blocking findings</b>", "cell"), P(str(len(gate_result.blocking)), "cell")],
                      [P("<b>Unknown severity</b>", "cell"), P(str(len(gate_result.unknown)), "cell")]]
                     + ([[P("<b>Required checks not run</b>", "cell"), P(_t(", ".join(gate_result.failed_checks)), "cell")]]
                        if gate_result.failed_checks else []),
                     [40 * mm, width - 40 * mm], header=False)]
    if gate_result.blocking:
        story.append(P("Reasons for failure: findings at or above the threshold",
                       "h2" if len(gate_result.blocking) <= 25 else "h2flow"))
        story.append(_table([["Severity", "Package", "Finding", "Type"]] + [
            [P(_sev(f.severity.value), "cell"), P(_t(f"{f.package}@{f.version}"), "mono"), P(_t(f.rule_or_advisory), "mono"),
             P(_t(type_label(f).split(" (")[0]), "cell")] for f in sorted(gate_result.blocking, key=priority_key)],
            [20 * mm, 50 * mm, 50 * mm, width - 120 * mm]))
    elif gate_result.failed_checks:
        story.append(P("The gate did not pass because required checks did not run.", "cell"))
    story.append(P("The same decision is reproduced in CI with: <font face='Courier'>python -m tracii scan --fail-on "
                   f"{pol.fail_on}</font> or the TRACII GitHub Action.", "small"))

    # 8. exports + limitations
    story += [P("7. Exports and limitations", "h1"),
              P(f"<b>CycloneDX 1.5 SBOM</b>: available for this scan (GET /api/scans/{_t(result.scan_id)}/sbom) - "
                f"{len({(p.name, p.version) for p in inv.packages})} components with purl, hash, scope, licence and the OSV advisories.", "cell"),
              P(f"<b>SARIF 2.1.0</b>: available for this scan (GET /api/scans/{_t(result.scan_id)}/sarif) - results point at "
                "package-lock.json for GitHub code scanning.", "cell"),
              Spacer(1, 4)]
    for line in ("No detected issue does not guarantee that the application is secure; results say what these checks detected.",
                 "Suspicious behaviour indicators are heuristics, not confirmed malware.",
                 "An advisory match means the installed version is in an affected range; it does not prove the vulnerable code is reachable or exploited.",
                 "Dependency paths show how a package is installed, not whether application code calls it.",
                 "Behaviour rules and GuardDog analyse only a prioritised subset of package tarballs; see Scan coverage.",
                 "Known-malware matching only covers already-reported malware.",
                 "AI assessments explain scanner evidence and never override the deterministic verdict.",
                 "Offline benchmark results are separate from this scan and are not reproduced here."):
        story.append(P(f"- {line}", "cell"))

    # appendix: every finding
    story += [PageBreak(), P("Appendix: all findings", "h1"),
              P(f"{len(findings)} findings, grouped by type, in priority order.", "small")]
    for label, group in (("Known malicious packages", mal), ("Known vulnerabilities", vulns),
                         ("Suspicious behaviour (heuristic)", sus), ("Repository posture", posture), ("Version diff", other)):
        if not group:
            continue
        story.append(P(f"{label} ({len(group)})", "h2" if len(group) <= 25 else "h2flow"))
        story.append(_table([["ID", "Severity", "Package", "Reference", "Source", "Via"]] + [
            [P(_t(f.id), "mono"), P(_sev(f.severity.value), "cell"), P(_t(f"{f.package}@{f.version}"), "mono"),
             P(_t(f.rule_or_advisory), "mono"), P(_t(SOURCE_LABEL.get(f.source, f.source)), "cell"),
             P(_t(", ".join(sorted({p.direct_dependency for p in f.paths})) or "-", 80) + (" (dev)" if _dev_only(f) else ""), "cell")]
            for f in sorted(group, key=priority_key)],
            [24 * mm, 17 * mm, 38 * mm, 38 * mm, 25 * mm, width - 142 * mm]))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=16 * mm, title=f"TRACII report - {src.label} - {result.scan_id}",
                            author="TRACII", subject="Supply-chain security assessment")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
