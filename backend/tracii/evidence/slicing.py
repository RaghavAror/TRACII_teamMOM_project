"""Focused code slices: send the model only the code around the evidence.

This is a lexical slicer (enclosing block + lines that define identifiers used
on the evidence line), NOT taint analysis. It keeps prompts small and every
slice tied to evidence IDs and exact line ranges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tracii.evidence.schema import Finding

MAX_SLICE_LINES = 60
IDENT = re.compile(r"[A-Za-z_$][\w$]*")
JS_KEYWORDS = {"const", "let", "var", "function", "return", "if", "else", "require", "new", "await",
               "async", "true", "false", "null", "undefined", "this", "process", "module", "exports"}


@dataclass
class Slice:
    file: str
    start: int
    end: int
    code: str
    evidence_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"file": self.file, "start": self.start, "end": self.end, "code": self.code,
                "evidence_ids": self.evidence_ids}


def _enclosing_block(lines: list[str], idx: int) -> tuple[int, int]:
    """Walk outwards to the nearest unbalanced '{' and its matching '}'."""
    depth, start = 0, 0
    for i in range(idx, -1, -1):
        depth += lines[i].count("}") - lines[i].count("{")
        if depth < 0:
            start = i
            break
    depth, end = 0, len(lines) - 1
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i >= idx:
            end = i
            break
    return start, end


def slice_for_lines(file: str, text: str, line_numbers: list[int], evidence_ids: list[str]) -> Slice:
    lines = text.splitlines()
    keep: set[int] = set()
    for ln in line_numbers:
        idx = max(0, min(ln - 1, len(lines) - 1))
        s, e = _enclosing_block(lines, idx)
        if e - s > MAX_SLICE_LINES:
            s, e = max(0, idx - 10), min(len(lines) - 1, idx + 10)
        keep.update(range(s, e + 1))
        # include definitions of identifiers used on the evidence line
        for name in set(IDENT.findall(lines[idx])) - JS_KEYWORDS:
            pat = re.compile(rf"\b(const|let|var|function)\s+{re.escape(name)}\b")
            keep.update(i for i, l in enumerate(lines) if pat.search(l))
    ordered = sorted(keep)[: MAX_SLICE_LINES * 2]
    out, prev = [], None
    for i in ordered:
        if prev is not None and i != prev + 1:
            out.append("    // ...")
        out.append(f"{i + 1:>5}| {lines[i]}")
        prev = i
    return Slice(file=file, start=ordered[0] + 1 if ordered else 0, end=ordered[-1] + 1 if ordered else 0,
                 code="\n".join(out), evidence_ids=evidence_ids)


def slices_for_finding(finding: Finding, files: dict[str, str]) -> list[Slice]:
    by_file: dict[str, list[tuple[int, str]]] = {}
    for ev in finding.evidence:
        if ev.file and ev.line and ev.file in files:
            by_file.setdefault(ev.file, []).append((ev.line, ev.id))
    return [slice_for_lines(f, files[f], [l for l, _ in items], [i for _, i in items])
            for f, items in by_file.items()]
