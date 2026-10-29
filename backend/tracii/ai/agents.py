"""Multi-agent investigation: one agent per standard methodology, then a judge.

Agents run in parallel, each only where its method applies to the finding:
- vuln_triage    CISA SSVC decision points + FIRST EPSS + CISA KEV     (known vulnerabilities)
- attack_mapping MITRE ATT&CK techniques for observed behaviour        (malicious indicators, version diffs)
- integrity      SLSA provenance + OpenSSF Scorecard + npm publishing  (every finding)
- threat_model   STRIDE over the dependency path into the app          (every finding)
- judge          reconciles the agents' cited claims; lists agreements and conflicts
Spark Open (open weights) re-runs the judge as an independent reviewer when configured.

Rules carried over from grounding.py: package text is untrusted data, every claim
must cite evidence IDs (scanner evidence + enrichment facts) or it is discarded,
and the model never changes the scanner's category or severity. Where a method
has a defined outcome (the SSVC table), Tracii computes it from the decision-point
values the agent cited; uncited values are left open and the outcome is a range.
"""

from __future__ import annotations

import csv
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import product
from pathlib import Path

import httpx

from tracii.ai import enrich, grounding
from tracii.ai.meta_client import ModelUnavailable, OpenAICompatClient
from tracii.ai.models import ROLES, open_weight_clients
from tracii.evidence.schema import Category, Finding
from tracii.evidence.slicing import Slice

_ROLE = {r.key: r for r in ROLES}

# ---------- SSVC (CISA coordinator table, pinned copy from CERTCC/SSVC) ----------

SSVC_ORDER = ["track", "track*", "attend", "act"]
SSVC_VALUES = {"exploitation": ["none", "public poc", "active"], "automatable": ["no", "yes"],
               "technical_impact": ["partial", "total"], "mission_impact": ["low", "medium", "high"]}


def _load_ssvc() -> dict[tuple[str, str, str, str], str]:
    rows = (line for line in (Path(__file__).parent / "ssvc_cisa.csv").read_text().splitlines()
            if not line.startswith("#"))
    return {(r[1], r[2], r[3], r[4]): r[5] for r in list(csv.reader(rows))[1:]}


SSVC_TABLE = _load_ssvc()


def ssvc_outcome(exploitation: str | None, automatable: str | None, technical_impact: str | None,
                 mission_impact: str) -> dict:
    """None = not established by cited evidence: every value is tried and the outcome becomes a range."""
    options = [[v] if v else SSVC_VALUES[k] for k, v in
               (("exploitation", exploitation), ("automatable", automatable), ("technical_impact", technical_impact))]
    outcomes = sorted({SSVC_TABLE[(e, a, t, mission_impact)] for e, a, t in product(*options)}, key=SSVC_ORDER.index)
    return {"decision": outcomes[-1], "range": outcomes, "settled": len(outcomes) == 1,
            "inputs": {"exploitation": exploitation, "automatable": automatable, "technical_impact": technical_impact,
                       "mission_impact": mission_impact},
            "table": "CISA SSVC coordinator v2.0.3 (CERTCC/SSVC)"}


# ---------- MITRE ATT&CK: closed list, so the model cannot invent technique IDs ----------

ATTACK_TECHNIQUES = {
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1546.016": "Event Triggered Execution: Installer Packages",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
    "T1082": "System Information Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1480": "Execution Guardrails",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1105": "Ingress Tool Transfer",
    "T1496": "Resource Hijacking",
    "T1485": "Data Destruction",
    "T1499": "Endpoint Denial of Service",
}
# fallback when no model is available: static-rule capability tag -> technique
TAG_TECHNIQUES = {"install_script": "T1546.016", "env_read": "T1552", "sensitive_file": "T1552.001",
                  "system_info": "T1082", "dynamic_eval": "T1059.007", "network": "T1071.001", "exec": "T1059"}

STRIDE = ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service",
          "elevation_of_privilege"]
CONTROLS = ["provenance", "source_link", "maintainers", "scorecard", "install_scripts"]
PRIORITIES = ["act_now", "attend", "track", "insufficient_evidence"]

# ---------- schemas (strict: every object closed, every property required) ----------

_IDS = {"type": "array", "items": {"type": "string"}}
_STR_LIST = {"type": "array", "items": {"type": "string"}}
_CLAIMS = grounding.INVESTIGATION_SCHEMA["properties"]["claims"]


def _obj(props: dict) -> dict:
    return {"type": "object", "additionalProperties": False, "required": list(props), "properties": props}


def _dp(values: list[str]) -> dict:
    return _obj({"value": {"type": "string", "enum": values}, "evidence_ids": _IDS})


def _agent_schema(method: dict) -> dict:
    return _obj({"summary": {"type": "string"}, "claims": _CLAIMS, "unknowns": _STR_LIST, "method": _obj(method)})


@dataclass(frozen=True)
class Agent:
    key: str
    methodology: str
    applies_to: tuple[Category, ...]
    instructions: str
    method_schema: dict


ALL = tuple(Category)
AGENTS = [
    Agent("vuln_triage", "CISA SSVC + FIRST EPSS + CISA KEV", (Category.VULNERABILITY,),
          "Method: CISA SSVC. Set each decision point ONLY from cited evidence:\n"
          "- exploitation: 'active' = reliable evidence of exploitation in the wild (e.g. a CISA KEV entry, or an "
          "advisory describing malware actually shipped); 'public poc' = a public exploit or proof of concept is "
          "documented in the evidence; 'none' = neither. EPSS is a probability, not proof of exploitation.\n"
          "- automatable: 'yes' if an attacker can reliably trigger it at scale without user interaction "
          "(e.g. CVSS AV:N/AC:L/PR:N/UI:N), else 'no'.\n"
          "- technical_impact: 'total' if exploitation gives full control of the component or total disclosure of "
          "its information, else 'partial'.\n"
          "If the evidence does not establish a value, give an empty evidence_ids list; Tracii will treat it as open. "
          "Do not decide the final SSVC outcome; Tracii computes it from the official table.",
          {"exploitation": _dp(SSVC_VALUES["exploitation"]), "automatable": _dp(SSVC_VALUES["automatable"]),
           "technical_impact": _dp(SSVC_VALUES["technical_impact"])}),
    Agent("attack_mapping", "MITRE ATT&CK technique mapping", (Category.MALICIOUS_INDICATOR, Category.VERSION_DIFF),
          "Method: MITRE ATT&CK (Enterprise). Map each behaviour that the evidence actually shows to a technique "
          "from the allowed list. One technique per distinct behaviour, each with the evidence IDs that show it and "
          "a one-sentence rationale. Do not map capabilities that are not in the evidence. A mapping describes what "
          "the code could do; it is not proof of intent.",
          {"techniques": {"type": "array", "items": _obj({
              "technique_id": {"type": "string", "enum": list(ATTACK_TECHNIQUES)}, "evidence_ids": _IDS,
              "rationale": {"type": "string"}})}}),
    Agent("integrity", "SLSA provenance + OpenSSF Scorecard", ALL,
          "Method: supply-chain integrity (SLSA build provenance, OpenSSF Scorecard, npm publishing signals). For "
          "each control that the evidence covers, rate it strong / weak / missing / unknown with citations. "
          "These are posture signals: weak posture is a risk factor, never evidence of malware.",
          {"controls": {"type": "array", "items": _obj({
              "control": {"type": "string", "enum": CONTROLS},
              "status": {"type": "string", "enum": ["strong", "weak", "missing", "unknown"]},
              "evidence_ids": _IDS})}}),
    Agent("threat_model", "STRIDE on the dependency path", ALL,
          "Method: STRIDE threat modelling of this package as a component of the user's app. Use the dependency "
          "paths (is it reached in production or only via devDependencies?), install-time behaviour and the finding. "
          "List only threats the evidence supports, one sentence each, with citations. Say in unknowns that "
          "reachability is path-level only (whether app code calls the affected function was not analysed).",
          {"threats": {"type": "array", "items": _obj({
              "stride": {"type": "string", "enum": STRIDE}, "threat": {"type": "string"}, "evidence_ids": _IDS})}}),
]

JUDGE_SCHEMA = _obj({"priority": {"type": "string", "enum": PRIORITIES}, "verdict": {"type": "string"},
                     "claims": _CLAIMS, "agreements": _STR_LIST, "conflicts": _STR_LIST, "next_steps": _STR_LIST,
                     "unknowns": _STR_LIST})

JUDGE_INSTRUCTIONS = """You are the judge over several methodology agents that investigated one finding.
Agent reports are model-generated: trust a statement only as far as the evidence IDs it cites.
1. Reconcile the reports. List where methods agree and where they conflict (e.g. high EPSS but dev-only path).
2. Choose a priority: act_now / attend / track, or insufficient_evidence. For known vulnerabilities, start from
   the computed SSVC outcome (act -> act_now, attend -> attend, track/track* -> track) and explain any departure.
3. Every claim must cite evidence IDs from the evidence index. Never invent IDs, CVEs, versions or hosts.
4. next_steps are concrete actions for the app owner (upgrade, pin, remove, review a file), most important first."""


# ---------- validation ----------

def _cited(items: list[dict], known: set[str]) -> tuple[list[dict], list[dict]]:
    kept, dropped = [], []
    for it in items or []:
        ids = [i for i in it.get("evidence_ids") or [] if isinstance(i, str)]
        (kept if ids and set(ids) <= known else dropped).append({**it, "evidence_ids": ids})
    return kept, dropped


def validate_agent(agent: Agent, raw: dict, known: set[str], mission_impact: str, facts: dict) -> dict:
    claims, bad_claims = _cited(raw.get("claims"), known)
    method = raw.get("method") or {}
    out: dict = {"summary": str(raw.get("summary", "")),
                 "claims": [{"text": str(c.get("text", "")), "evidence_ids": c["evidence_ids"]} for c in claims],
                 "discarded_claims": [{"text": str(c.get("text", ""))[:300], "evidence_ids": c["evidence_ids"],
                                       "reason": "cites no or unknown evidence IDs"} for c in bad_claims],
                 "unknowns": [str(u) for u in raw.get("unknowns") or []]}
    if agent.key == "vuln_triage":
        dps = {}
        for k in ("exploitation", "automatable", "technical_impact"):
            dp = method.get(k) or {}
            ids = [i for i in dp.get("evidence_ids") or [] if i in known]
            ok = dp.get("value") in SSVC_VALUES[k] and ids
            dps[k] = {"value": dp.get("value") if ok else None, "evidence_ids": ids if ok else []}
            if not ok:
                out["unknowns"].append(f"SSVC {k} not established by cited evidence; left open.")
        if facts.get("in_kev"):   # a KEV listing is authoritative for 'active'
            dps["exploitation"] = {"value": "active", "evidence_ids": [i for i in known if "-x-kev-" in i]}
        out["method"] = dps
        out["ssvc"] = ssvc_outcome(dps["exploitation"]["value"], dps["automatable"]["value"],
                                   dps["technical_impact"]["value"], mission_impact)
    else:
        list_key = {"attack_mapping": "techniques", "integrity": "controls", "threat_model": "threats"}[agent.key]
        kept, dropped = _cited(method.get(list_key), known)
        if agent.key == "attack_mapping":
            kept = [{**t, "name": ATTACK_TECHNIQUES[t["technique_id"]]} for t in kept
                    if t.get("technique_id") in ATTACK_TECHNIQUES]
        out["method"] = {list_key: kept}
        out["discarded_claims"] += [{"text": json.dumps({k: v for k, v in d.items() if k != "evidence_ids"})[:300],
                                     "evidence_ids": d["evidence_ids"], "reason": f"{list_key} item without valid citation"}
                                    for d in dropped]
    return out


def fallback_agent(agent: Agent, finding: Finding, evidence: list, mission_impact: str, facts: dict) -> dict:
    """No model: deterministic, labelled output from the same evidence."""
    out: dict = {"summary": "Model unavailable: deterministic result from the evidence only.",
                 "claims": [{"text": e.summary, "evidence_ids": [e.id]} for e in evidence
                            if e.kind in ("threat_intel", "metadata")][:6],
                 "discarded_claims": [], "unknowns": []}
    if agent.key == "vuln_triage":
        kev_ids = [e.id for e in evidence if "-x-kev-" in e.id]
        out["method"] = {"exploitation": {"value": "active" if kev_ids else None, "evidence_ids": kev_ids},
                         "automatable": {"value": None, "evidence_ids": []},
                         "technical_impact": {"value": None, "evidence_ids": []}}
        out["ssvc"] = ssvc_outcome("active" if kev_ids else None, None, None, mission_impact)
    elif agent.key == "attack_mapping":
        seen, techniques = set(), []
        for e in finding.evidence:
            for tag, tid in TAG_TECHNIQUES.items():
                if (tag in e.summary or (tag == "install_script" and e.kind == "install_script")) and tid not in seen:
                    seen.add(tid)
                    techniques.append({"technique_id": tid, "name": ATTACK_TECHNIQUES[tid], "evidence_ids": [e.id],
                                       "rationale": f"static-rule tag '{tag}' (deterministic mapping)"})
        out["method"] = {"techniques": techniques}
    else:
        out["method"] = {"controls": []} if agent.key == "integrity" else {"threats": []}
    return out


# ---------- orchestration ----------

def _evidence_index(finding: Finding, extra: list) -> Finding:
    """Same finding, evidence extended with enrichment facts, so prompt + validation see one ID space."""
    return finding.model_copy(update={"evidence": [*finding.evidence, *extra]})


def _run_agent(agent: Agent, f: Finding, slices: list[Slice], patterns: list[dict], paths: list[str],
               client: OpenAICompatClient, mission_impact: str, facts: dict) -> dict:
    model = _ROLE["investigator"].model_id
    known = {e.id for e in f.evidence}
    base = {"agent": agent.key, "methodology": agent.methodology}
    t = time.perf_counter()
    try:
        raw = client.chat_json(model, grounding.SYSTEM_PROMPT + "\n\n" + agent.instructions,
                               grounding.build_user_prompt(f, slices, patterns, paths),
                               _agent_schema(agent.method_schema), f"tracii_{agent.key}", reasoning_effort="medium")
        res = {**base, "model": model, "ai_status": "ok", **validate_agent(agent, raw, known, mission_impact, facts)}
    except ModelUnavailable as exc:
        res = {**base, "model": None, "ai_status": "unavailable", "ai_error": str(exc)[:200],
               **fallback_agent(agent, f, f.evidence, mission_impact, facts)}
    res["latency_s"] = round(time.perf_counter() - t, 2)
    return res


def _judge_prompt(f: Finding, reports: list[dict]) -> str:
    evidence = [{"evidence_id": e.id, "kind": e.kind, "summary": e.summary} for e in f.evidence]
    slim = [{k: r.get(k) for k in ("agent", "methodology", "ai_status", "summary", "claims", "method", "ssvc", "unknowns")}
            for r in reports]
    facts = {"finding_id": f.id, "category": f.category.value, "package": f"{f.package}@{f.version}",
             "rule_or_advisory": f.rule_or_advisory, "scanner_severity": f.severity.value,
             "fixed_versions": f.fixed_versions,
             "dependency_paths": [{"path": " -> ".join(p.nodes), "dev_only": p.dev_only} for p in f.paths[:3]]}
    return (f"SCANNER FINDING (trusted):\n{json.dumps(facts, indent=1)}\n\n"
            f"EVIDENCE INDEX (cite these IDs):\n{json.dumps(evidence, indent=1)}\n\n"
            f"AGENT REPORTS (model-generated; verify against evidence):\n{json.dumps(slim, indent=1)}\n\n"
            "Return the JSON object described by the schema.")


def _validate_judge(raw: dict, known: set[str]) -> dict:
    claims, bad = _cited(raw.get("claims"), known)
    return {"priority": raw.get("priority") if raw.get("priority") in PRIORITIES else "insufficient_evidence",
            "verdict": str(raw.get("verdict", "")),
            "claims": [{"text": str(c.get("text", "")), "evidence_ids": c["evidence_ids"]} for c in claims],
            "discarded_claims": [{"text": str(c.get("text", ""))[:300], "evidence_ids": c["evidence_ids"],
                                  "reason": "cites no or unknown evidence IDs"} for c in bad],
            **{k: [str(x) for x in raw.get(k) or []] for k in ("agreements", "conflicts", "next_steps", "unknowns")}}


def _fallback_judge(f: Finding, reports: list[dict]) -> dict:
    ssvc = next((r["ssvc"] for r in reports if r.get("ssvc")), None)
    priority = ({"act": "act_now", "attend": "attend"}.get(ssvc["decision"], "track") if ssvc and ssvc["settled"]
                else "insufficient_evidence")
    return {"priority": priority, "verdict": "Model unavailable: priority taken from the computed SSVC outcome "
                                             "where it is settled, otherwise left as insufficient_evidence.",
            "claims": [], "discarded_claims": [], "agreements": [], "conflicts": [],
            "next_steps": [f"Upgrade {f.package} to {f.fixed_versions[0]} or later." if f.fixed_versions
                           else f"Review {f.package}@{f.version} before trusting it."],
            "unknowns": ["No model reconciled the agent reports."]}


def _judge(client: OpenAICompatClient, model: str, system: str, prompt: str, known: set[str], f: Finding,
           reports: list[dict]) -> dict:
    t = time.perf_counter()
    try:
        raw = client.chat_json(model, system, prompt, JUDGE_SCHEMA, "tracii_judge", reasoning_effort="medium")
        out = {"model": model, "ai_status": "ok", **_validate_judge(raw, known)}
    except ModelUnavailable as exc:
        out = {"model": None, "ai_status": "unavailable", "ai_error": str(exc)[:200], **_fallback_judge(f, reports)}
    out["latency_s"] = round(time.perf_counter() - t, 2)
    return out


def _review(name: str, client: OpenAICompatClient, model: str, system: str, prompt: str, known: set[str]) -> dict:
    t = time.perf_counter()
    try:
        v = _validate_judge(client.chat_json(model, system, prompt, JUDGE_SCHEMA, "tracii_judge", strict=False,
                                             max_tokens=OPEN_WEIGHT_MAX_TOKENS), known)
        return {"assessor": name, "model": model, "status": "ok", "priority": v["priority"], "verdict": v["verdict"],
                "claims": v["claims"], "discarded_claims": v["discarded_claims"],
                "latency_s": round(time.perf_counter() - t, 2)}
    except ModelUnavailable as exc:
        return {"assessor": name, "model": model, "status": "unavailable", "error": str(exc)[:200]}


# reasoning open-weight models (Glimmer) think before answering; leave room for both
OPEN_WEIGHT_MAX_TOKENS = 16000

# Background open-weight reviews: a slow free endpoint must not hold up the judge's answer.
_REVIEW_POOL = ThreadPoolExecutor(max_workers=4)
_REVIEWS: dict[str, dict] = {}
_REVIEW_LOCK = threading.Lock()
_MAX_REVIEW_JOBS = 200


def _start_reviews(reviewers: dict, system: str, prompt: str, known: set[str]) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _REVIEW_LOCK:
        if len(_REVIEWS) >= _MAX_REVIEW_JOBS:
            _REVIEWS.pop(next(iter(_REVIEWS)))
        _REVIEWS[job_id] = {"judge_priority": None,
                            "reviews": {n: {"assessor": n, "model": m, "status": "pending"}
                                        for n, (_, m) in reviewers.items()}}

    def run(name: str, c: OpenAICompatClient, model: str) -> None:
        result = _review(name, c, model, system, prompt, known)
        with _REVIEW_LOCK:
            _REVIEWS[job_id]["reviews"][name] = result

    for name, (c, m) in reviewers.items():
        _REVIEW_POOL.submit(run, name, c, m)
    return job_id


def review_status(job_id: str) -> dict | None:
    with _REVIEW_LOCK:
        job = _REVIEWS.get(job_id)
        if job is None:
            return None
        reviews = [dict(r) for r in job["reviews"].values()]
        judge_priority = job["judge_priority"]
    for r in reviews:
        if r["status"] == "ok" and judge_priority:
            r["agrees_with_judge"] = r["priority"] == judge_priority
    return {"review_id": job_id, "done": all(r["status"] != "pending" for r in reviews), "reviews": reviews}


def investigate(finding: Finding, slices: list[Slice], client: OpenAICompatClient, *,
                mission_impact: str = "medium", http: httpx.Client | None = None,
                independent: bool = True, defer_reviews: bool = False) -> dict:
    """defer_reviews=True returns once the judge is done; reviews continue in the background
    and are read with review_status(review_id)."""
    if mission_impact not in SSVC_VALUES["mission_impact"]:
        raise ValueError("mission_impact must be low, medium or high")
    t0 = time.perf_counter()
    own = http is None
    http = http or httpx.Client(timeout=20, follow_redirects=True)
    try:
        jobs = [enrich.provenance]
        if finding.category == Category.VULNERABILITY:
            jobs.append(enrich.threat_intel)
        with ThreadPoolExecutor(max_workers=2) as pool:
            parts = list(pool.map(lambda fn: fn(finding, http), jobs))
    finally:
        if own:
            http.close()
    extra = [e for p in parts for e in p.evidence]
    facts = {k: v for p in parts for k, v in p.facts.items()}
    f = _evidence_index(finding, extra)
    paths = [" -> ".join(p.nodes) + (" (dev only)" if p.dev_only else "") for p in finding.paths[:3]]
    patterns = grounding.retrieve_threat_patterns(grounding.finding_tags(finding))
    active = [a for a in AGENTS if finding.category in a.applies_to]
    with ThreadPoolExecutor(max_workers=len(active)) as pool:
        reports = list(pool.map(lambda a: _run_agent(a, f, slices, patterns, paths, client, mission_impact, facts),
                                active))

    known = {e.id for e in f.evidence}
    prompt = _judge_prompt(f, reports)
    system = grounding.SYSTEM_PROMPT + "\n\n" + JUDGE_INSTRUCTIONS
    reviewers = open_weight_clients() if independent else {}
    review_id = _start_reviews(reviewers, system, prompt, known) if defer_reviews and reviewers else None
    # judge and (non-deferred) open-weight reviewers see the same prompt and run side by side
    inline = {} if defer_reviews else reviewers
    with ThreadPoolExecutor(max_workers=1 + len(inline)) as pool:
        judge_job = pool.submit(_judge, client, _ROLE["deep"].model_id, system, prompt, known, f, reports)
        review_jobs = [pool.submit(_review, name, c, m, system, prompt, known) for name, (c, m) in inline.items()]
        judge = judge_job.result()
        reviews = [j.result() for j in review_jobs]
    for r in reviews:
        if r["status"] == "ok":
            r["agrees_with_judge"] = r["priority"] == judge["priority"]
    if review_id:
        with _REVIEW_LOCK:
            _REVIEWS[review_id]["judge_priority"] = judge["priority"]
        reviews = review_status(review_id)["reviews"]

    return {"finding_id": finding.id, "scanner_category": finding.category.value,
            "scanner_severity": finding.severity.value, "mission_impact_assumed": mission_impact,
            "enrichment": {"evidence": [e.model_dump() for e in extra],
                           "limitations": [lim for p in parts for lim in p.limitations]},
            "agents": reports, "skipped_agents": [{"agent": a.key, "methodology": a.methodology,
                                                   "reason": f"not applicable to {finding.category.value}"}
                                                  for a in AGENTS if a not in active],
            "judge": judge, "independent_review": reviews, "review_id": review_id,
            "elapsed_s": round(time.perf_counter() - t0, 2)}
