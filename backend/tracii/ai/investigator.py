"""AI investigation entry points. Every path degrades to a labelled deterministic result."""

from __future__ import annotations

import json

from tracii.ai import grounding
from tracii.ai.meta_client import ModelUnavailable, OpenAICompatClient
from tracii.ai.models import ROLES, open_weight_clients
from tracii.evidence.schema import Finding, ScanResult
from tracii.evidence.slicing import Slice

_ROLE = {r.key: r for r in ROLES}


def explain(finding: Finding, slices: list[Slice], client: OpenAICompatClient, deep: bool = False) -> dict:
    paths = [" -> ".join(p.nodes) for p in finding.paths[:3]]
    patterns = grounding.retrieve_threat_patterns(grounding.finding_tags(finding))
    role = _ROLE["deep" if deep else "investigator"]
    base = {"finding_id": finding.id, "scanner_category": finding.category.value,
            "scanner_severity": finding.severity.value, "slices": [s.as_dict() for s in slices],
            "threat_patterns": [p["id"] for p in patterns]}
    try:
        raw = client.chat_json(
            role.model_id, grounding.SYSTEM_PROMPT, grounding.build_user_prompt(finding, slices, patterns, paths),
            grounding.INVESTIGATION_SCHEMA, "tracii_investigation",
            reasoning_effort="high" if deep else "medium")
        return {**base, "model": role.model_id, "ai_status": "ok", **grounding.validate_investigation(raw, finding)}
    except ModelUnavailable as exc:
        return {**base, "model": None, "ai_status": "unavailable", "ai_error": str(exc)[:200],
                **grounding.deterministic_summary(finding, paths)}


def independent_assessments(finding: Finding, slices: list[Slice], primary: dict) -> list[dict]:
    """Ask configured open-weight models for a second opinion; report agreement, never override."""
    out = []
    paths = [" -> ".join(p.nodes) for p in finding.paths[:3]]
    prompt = grounding.build_user_prompt(finding, slices, [], paths)
    for name, (client, model) in open_weight_clients().items():
        try:
            raw = client.chat_json(model, grounding.SYSTEM_PROMPT, prompt, grounding.INVESTIGATION_SCHEMA,
                                   "tracii_investigation", strict=False)
            v = grounding.validate_investigation(raw, finding)
            out.append({"assessor": name, "model": model, "status": "ok", "assessment": v["assessment"],
                        "agrees_with_primary": v["assessment"] == primary.get("assessment"),
                        "claims": v["claims"], "discarded_claims": v["discarded_claims"]})
        except ModelUnavailable as exc:
            out.append({"assessor": name, "model": model, "status": "unavailable", "error": str(exc)[:200]})
    return out


def answer_question(question: str, scan: ScanResult, client: OpenAICompatClient) -> dict:
    compact = [{"finding_id": f.id, "category": f.category.value, "package": f"{f.package}@{f.version}",
                "rule": f.rule_or_advisory, "severity": f.severity.value, "title": f.title,
                "fixed_versions": f.fixed_versions,
                "paths": [" -> ".join(p.nodes) for p in f.paths[:2]]} for f in scan.findings[:80]]
    checks = [c.model_dump() for c in scan.checks]
    user = ("SCAN CONTEXT (trusted):\n" + json.dumps({"summary": scan.summary(), "checks": checks,
                                                     "findings": compact}, indent=1)
            + f"\n\nUSER QUESTION:\n{question[:2000]}\n\nAnswer only from the scan context and cite finding_ids. "
              "If the scan cannot answer it, say so in unknowns.")
    ids = {f.id for f in scan.findings}
    try:
        raw = client.chat_json(_ROLE["investigator"].model_id, grounding.SYSTEM_PROMPT, user,
                               grounding.QA_SCHEMA, "tracii_answer", reasoning_effort="low")
        return {"ai_status": "ok", **grounding.validate_answer(raw, ids)}
    except ModelUnavailable as exc:
        return {"ai_status": "unavailable", "answer": "AI Q&A is unavailable; the findings list is still complete.",
                "cited_finding_ids": [], "unknowns": [str(exc)[:200]]}
