# Tracii architecture

## Flow

```
                 ┌──────────────────────── Frontend (static, Vercel) ────────────────────────┐
                 │ intake · checks · summary (per category) · findings · evidence · path ·    │
                 │ AI explain · fix diff · rescan compare · version diff · ask (text/voice)   │
                 └───────────────────────────────┬────────────────────────────────────────────┘
                                                 │ JSON over HTTPS (no keys in browser)
┌────────────────────────────────── FastAPI backend (Render, Docker) ───────────────────────────────────┐
│                                                                                                        │
│ 1 INTAKE        github.py: URL → commit SHA → raw package.json + package-lock.json (no clone/install)  │
│                 upload: two JSON files, size-capped, validated synchronously (400 on malformed)       │
│        ↓                                                                                               │
│ 2 INVENTORY     lockfile.py: v1/v2/v3 → PackageNode{name, exact version, path, direct, dev,            │
│                 hasInstallScript, resolved deps via npm nested resolution}                             │
│        ↓                                                                                               │
│ 3 DETECT        ┌─ osv.py ─────────────── known vulnerabilities (OSV-Scanner CLI or OSV.dev API)        │
│   (separate     ├─ npm_registry.py ────── prioritised tarballs: sha512-verified, in-memory, no links    │
│    channels)    ├─ static_rules.py ────── Tracii rules + source→transform→sink attack chains            │
│                 ├─ guarddog.py ────────── GuardDog in Docker --network none, read-only mount            │
│                 └─ (Scorecard) ────────── repository posture: optional, never malware evidence          │
│        ↓                                                                                               │
│ 4 NORMALIZE     schema.py: Finding{category, source, rule, pkg@ver, severity, confidence,              │
│                 evidence[id,file,line,snippet,url], paths, fixed_versions, limitations, status}         │
│        ↓                                                                                               │
│ 5 IMPACT        paths.py: shortest path per direct dependency, dev-only flag                           │
│        ↓                                                                                               │
│ 6 EXPLAIN       slicing.py → grounding.py → investigator.py                                            │
│   (on demand)   Muse Spark 1.3 (default) | Muse Wonder (deep) | Glimmer/Spark Open (2nd opinion)       │
│                 strict JSON schema, claims must cite evidence IDs, ungrounded claims discarded         │
│        ↓                                                                                               │
│ 7 FIX+VERIFY    remediation.py: proposal diff → npm --package-lock-only --ignore-scripts → rescan      │
│                 → fixed / remaining / new / newly_covered; VERIFIED only if a rescan really ran         │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Key decisions

| Decision | Why |
|---|---|
| Python FastAPI instead of chainviz's Jac backend | Jac is niche; chainviz needed a workaround module (`graph_store.py`) because jac-scale didn't persist graphs across requests. FastAPI + pydantic gives typed contracts, easy tests and a Render deploy. |
| No database | Scans live in memory (`pipeline.STORE`). Scan history isn't a demo requirement; add SQLite only if it becomes one. |
| Deep (tarball) scans only on a prioritised subset | Install-script packages first, then direct deps; `DEEP_SCAN_LIMIT` (default 15). Skipped counts are shown in the "What was checked" panel. |
| GuardDog via Docker on the dev box, pip on Render | GuardDog's Semgrep dependency conflicts with Python 3.14 in Codespaces; the Render image uses Python 3.12. |
| Fix verification by `npm install --package-lock-only --ignore-scripts` | It resolves real versions from the registry without unpacking tarballs or running lifecycle scripts. It runs in a temp dir, never in the user's repo. |
| Static frontend, no build step | Fewer moving parts for a 1-week build. All untrusted text is rendered with `textContent`. |

## API contract (v0.1)

| Method & path | Body | Returns |
|---|---|---|
| `GET /api/health` | – | `{ok}` |
| `GET /api/models/status` | – | rows `{role, model, feature, endpoint, optional, status}` |
| `POST /api/scan/github` | `{url, subdir?, deep_scan_limit?}` | `{scan_id, status}` (async) |
| `POST /api/scan/upload` | multipart `package_json`, `package_lock` | `{scan_id, status}`; 400 malformed, 413 too large |
| `POST /api/scan/fixture` | `{name}` | `{scan_id, status}` |
| `GET /api/scans/{id}` | – | `{status, progress[], error, result: ScanResult, summary}` |
| `GET /api/scans/{id}/graph` | – | `{nodes, edges, roots}` |
| `POST /api/scans/{id}/findings/{fid}/explain` | `{deep?, independent?}` | investigation (see below) |
| `POST /api/scans/{id}/findings/{fid}/fix` | – | `FixProposal{kind, to_version, reason, caveats, diff, new_package_json}` |
| `POST /api/scans/{id}/findings/{fid}/rescan` | – | `{status: verified_fixed\|still_present\|unverified, comparison{fixed,remaining,new,newly_covered}, new_package_lock}` |
| `POST /api/diff` | `{package, old_version, new_version}` | diff report + `version_diff` findings |
| `POST /api/scans/{id}/ask` | `{question}` | `{answer, cited_finding_ids, unknowns, ai_status}` |
| `POST /api/scans/{id}/ask/voice` | multipart `audio` (WAV 16 kHz mono) | `{transcript, answer, …}` |
| `POST /api/scans/{id}/report/image` | – | `{label:"AI-generated illustration. Not evidence.", image_b64}`; 404 unless `ENABLE_REPORT_IMAGES=1` |
| `POST /api/evidence/segment` | multipart `image` (PNG/JPEG), `prompt` | `{boxes[], interpretation, note}` |

### Investigation output (model-facing strict schema + server fields)

```json
{
  "finding_id": "…", "scanner_category": "malicious_indicator", "scanner_severity": "high",
  "model": "muse-spark-1.3", "ai_status": "ok | unavailable",
  "observed": "…", "why_it_matters": "…",
  "claims": [{"text": "…", "evidence_ids": ["<id>-e0"]}],
  "discarded_claims": [{"text": "…", "reason": "cites no or unknown evidence IDs"}],
  "assessment": "consistent_with_malicious | consistent_with_benign | known_vulnerability_applies | insufficient_evidence | unclear",
  "confidence": "high | medium | low", "unknowns": [], "benign_explanations": [], "next_action": "…",
  "slices": [{"file": "setup.js", "start": 5, "end": 15, "code": "…", "evidence_ids": []}],
  "threat_patterns": ["TP-001"],
  "independent_assessments": [{"assessor": "glimmer", "assessment": "…", "agrees_with_primary": true}]
}
```

The scanner's category and severity are returned alongside the AI output, unchanged. The model's schema has no field that could alter them.

## Security controls (where they live)

| Rule | Enforcement |
|---|---|
| Never run install scripts | No `npm install` with tarballs anywhere; fix simulation uses `--package-lock-only --ignore-scripts` plus `npm_config_ignore_scripts=true`. |
| Untrusted archives | `npm_registry.extract_in_memory`: integrity check, rejects symlinks, hardlinks, absolute paths and `..`; size and file-count caps. Tests: `test_detectors.py`. |
| Untrusted uploads | Size caps, JSON validation before a job starts; no ZIP uploads in the MVP. |
| Prompt injection | Package text is fenced in `<untrusted_package_data>`; strict schema; claim-ID validation. Test: `test_prompt_injection_text_is_fenced_as_untrusted_data`. |
| Keys | Backend env only (`META_API_KEY`); the frontend `config.js` holds just the API URL. Error messages are truncated so request bodies are not echoed. |
| Honest status | `CheckRun` per detector (`ran`/`failed`/`not_configured`/`skipped`); model "verified" only after a real call. |
