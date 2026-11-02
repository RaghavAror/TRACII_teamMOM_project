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
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from tracii.evidence.schema import Category, Finding, ScanResult
from tracii.gate import GateResult

SEV = ["critical", "high", "medium", "low", "info", "unknown"]
SEV_COLOR = {"critical": "#9b1c1c", "high": "#d92d20", "medium": "#c27803", "low": "#2e78c7",
             "info": "#7d8796", "unknown": "#7d8796"}
INK, MUTED, LINE, SOFT = colors.HexColor("#0b1220"), colors.HexColor("#5b6577"), colors.HexColor("#e3e8f0"), colors.HexColor("#f4f6fb")
ACCENT, ACCENT2 = colors.HexColor("#0866ff"), colors.HexColor("#7c3aed")
SOURCE_LABEL = {"osv-api": "OSV.dev API", "osv-scanner": "OSV-Scanner", "guarddog": "GuardDog (DataDog)",
                "tracii-static": "TRACII behaviour rules"}
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


def what(f: Finding) -> str:
    """One line describing the finding: for malware and heuristics the evidence is the point, for advisories the title."""
    if f.category == Category.MALICIOUS_INDICATOR and f.evidence:
        return f.evidence[0].summary
    return f.title


def short_action(f: Finding) -> str:
    """One line: what to do about this finding (the full reasoning stays in the app)."""
    via = sorted({p.direct_dependency for p in f.paths})
    if is_known_malware(f):
        return "Remove this version" + (f" (arrives via {', '.join(via)})" if via else "") + "; treat secrets where it was installed as exposed."
    if f.category == Category.VULNERABILITY:
        if not f.fixed_versions:
            return "No fix published: check whether the affected feature is used; consider replacing the package."
        if _direct(f):
            return f"Upgrade to {f.fixed_versions[0]}."
        return f"Upgrade {', '.join(via) or 'the parent'} to a release with {f.package} >= {f.fixed_versions[0]}, or add an npm override."
    if f.category == Category.MALICIOUS_INDICATOR:
        return "Review the cited code before trusting this version."
    return "Review the evidence in TRACII."


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
        "title": ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=INK),
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
    outcome = gate_result.outcome.upper()
    pol = gate_result.policy
    gate_color = "#12805c" if gate_result.outcome == "pass" else "#d92d20" if gate_result.outcome == "fail" else "#c27803"
    verdict = (f"{len(mal)} known malicious package(s) in the dependency tree" if mal else
               f"{len(gate_result.blocking)} blocking finding(s) at severity {pol.fail_on} or above"
               if gate_result.outcome == "fail" else
               "No blocking findings from the checks that ran" if gate_result.outcome == "pass" else
               "Scan incomplete: a required check did not run")

    def sev_counts(group: list[Finding]) -> str:
        parts = [f"{sum(1 for f in group if f.severity.value == s)} {s}" for s in SEV if any(f.severity.value == s for f in group)]
        return f"<b>{len(group)}</b>" + (f" ({', '.join(parts)})" if parts else "")

    # 1. title + verdict (everything a reader needs is on the first page)
    story += [Spacer(1, 4 * mm), P("TRACII SUPPLY-CHAIN SECURITY REPORT", "kicker"), Spacer(1, 2),
              P(_t(project), "title"), Spacer(1, 4),
              P(f"Scanned {_t(scanned)} - {len(inv.packages)} packages ({direct} direct) - lockfile v{inv.lockfile_version}"
                f" - scan <font face='Courier'>{_t(result.scan_id)}</font>"
                + (f" - rescan of <font face='Courier'>{_t(result.parent_scan_id)}</font>" if result.parent_scan_id else ""), "small"),
              Spacer(1, 8)]
    box = Table([[P(f'<font color="{gate_color}"><b>CI gate: {outcome}</b></font>  '
                    f'<font color="#5b6577">fail on {_t(pol.fail_on)} - exit code {gate_result.exit_code}</font>', "h2")],
                 [P(f"<b>{_t(verdict)}.</b> Deterministic scanner verdict; no AI involved.")],
                 [P(f"Known malicious packages {sev_counts(mal)}  -  Known vulnerabilities {sev_counts(vulns)}  -  "
                    f"Suspicious behaviour {sev_counts(sus)}" + (f"  -  Repository posture {sev_counts(posture)}" if posture else "")
                    + (f"  -  Version diff {sev_counts(other)}" if other else ""), "cell")]],
                colWidths=[width], hAlign="LEFT")
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(gate_color)),
                             ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 4),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(box)

    # 2. fix first
    if ranked:
        story += [P("Fix first", "h1"),
                  P("Ordered by scanner facts only: known malware, severity, ships to production, direct dependency, fix available.", "small"),
                  _table([["#", "Package", "Issue", "What to do"]] + [
                      [str(i + 1), P(_t(f"{f.package}@{f.version}"), "mono"),
                       P(f"{_sev(f.severity.value)} {_t(f.rule_or_advisory)}<br/>{_t(what(f), 90)}", "cell"),
                       P(_t(short_action(f)), "cell")]
                      for i, f in enumerate(ranked[:5])], [7 * mm, 40 * mm, 62 * mm, width - 109 * mm])]

    # 3. where the risk comes from (impact map as a table)
    via: dict[str, dict] = {}
    for f in ranked:
        for p in f.paths:
            d = via.setdefault(p.direct_dependency, {"pkgs": set(), "worst": f, "dev": True})
            d["pkgs"].add(f"{f.package}@{f.version}")
            d["dev"] = d["dev"] and p.dev_only
            if priority_key(f) < priority_key(d["worst"]):
                d["worst"] = f
    if via:
        story += [P("Where the risk comes from", "h1"),
                  P("Each direct dependency and the risky packages it brings in. Upgrading the dependency at the top of a chain can clear everything below it.", "small"),
                  _table([["Direct dependency", "Risky packages via it", "Worst", "Ships"]] + [
                      [P(_t(dep), "mono"), P(_t(", ".join(sorted(d["pkgs"])), 300), "mono"), P(_sev(d["worst"].severity.value), "cell"),
                       "dev only" if d["dev"] else "production"]
                      for dep, d in sorted(via.items(), key=lambda kv: (priority_key(kv[1]["worst"]), -len(kv[1]["pkgs"])))[:10]],
                      [38 * mm, width - 90 * mm, 26 * mm, 26 * mm])]

    # 4. all findings, one row each, grouped by type
    story.append(P("All findings", "h1"))
    if not ranked:
        story.append(P("No findings above info level from the checks that ran."))
    for group in (mal, vulns, sus, posture, other):
        rows = sorted((f for f in group if f.severity.value != "info"), key=priority_key)
        if not rows:
            continue
        story.append(P(f"{_t(type_label(rows[0]))} - {len(rows)}", "h2" if len(rows) <= 25 else "h2flow"))
        story.append(_table([["Severity", "Package", "Finding", "Fix or next step", "Via"]] + [
            [P(_sev(f.severity.value), "cell"), P(_t(f"{f.package}@{f.version}"), "mono"),
             P(f"<font face='Courier'>{_t(f.rule_or_advisory)}</font><br/><font color='#5b6577'>{_t(what(f), 90)}</font>", "cell"),
             P(_t(short_action(f), 140), "cell"),
             P(_t(", ".join(sorted({p.direct_dependency for p in f.paths})) or "-", 60) + (" (dev)" if _dev_only(f) else ""), "cell")]
            for f in rows], [18 * mm, 36 * mm, 52 * mm, width - 134 * mm, 28 * mm]))
    info = [f for f in findings if f.severity.value == "info"]
    if info:
        story.append(P(f"{len(info)} context-only signal(s), such as packages that run an install script, are not listed; "
                       "they are in the SARIF and JSON exports and in the app.", "small"))

    # 5. AI notes, only when a model call actually succeeded for this scan
    by_id = {f.id: f for f in findings}
    ai_rows = [(by_id[fid], note) for fid, note in ai_notes.items() if fid in by_id]
    story.append(P("AI investigation", "h1"))
    if not ai_rows:
        story.append(P("No AI investigation was run for this scan, so this report contains no AI content.", "small"))
    else:
        story.append(P("Assessments explain the scanner's evidence; every claim cites an evidence ID and none changes the scanner verdict.", "small"))
    for f, note in ai_rows:
        lines = [f"<b>{_t(f.package)}@{_t(f.version)} - {_t(f.rule_or_advisory)}</b>"]
        if ex := note.get("explain"):
            lines.append(f"{_t(ex.get('model'))}: {_t(ex.get('assessment'))}, confidence {_t(ex.get('confidence'))}"
                         + (f". {_t(ex.get('observed'), 300)}" if ex.get("observed") else ""))
            lines += [f"- {_t(c.get('text'), 240)} <font color='#5b6577'>[evidence {_t(', '.join(c.get('evidence_ids') or []))}]</font>"
                      for c in (ex.get("claims") or [])[:3]]
        if ag := note.get("agents"):
            j = ag.get("judge") or {}
            lines.append(f"Agents judge ({_t(j.get('model'))}): priority {_t(j.get('priority'))}. {_t(j.get('verdict'), 300)}")
        story.append(P("<br/>".join(lines), "cell"))
        story.append(Spacer(1, 3))

    # 6. coverage + limitations
    story += [P("Coverage and limitations", "h1"),
              _table([["Check", "Status", "Detail"]] + [
                  [P(f"<b>{_t(c.name)}</b>", "cell"),
                   P(f'<font color="{"#12805c" if c.status == "ran" else "#c27803" if c.status in ("skipped", "not_configured") else "#d92d20"}">'
                     f"<b>{_t(c.status.replace('_', ' ').upper())}</b></font>", "cell"),
                   P(_t(c.detail, 110), "small")] for c in result.checks],
                  [32 * mm, 28 * mm, width - 60 * mm])]
    for w in inv.warnings[:3]:
        story.append(P(f"Inventory warning: {_t(w)}", "small"))
    story.append(P("- No finding is not a guarantee of safety: results say what these checks detected. A check that did not run is never a pass.<br/>"
                   "- An advisory match means the installed version is affected; it does not prove the vulnerable code is used.<br/>"
                   "- Suspicious behaviour is a heuristic, not confirmed malware; the known-malware list only covers reported malware.<br/>"
                   f"- Same gate in CI: <font face='Courier'>python -m tracii scan --fail-on {_t(pol.fail_on)}</font>. "
                   "SBOM (CycloneDX) and SARIF exports are available for this scan in TRACII.", "small"))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=16 * mm, title=f"TRACII report - {src.label} - {result.scan_id}",
                            author="TRACII", subject="Supply-chain security assessment")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
