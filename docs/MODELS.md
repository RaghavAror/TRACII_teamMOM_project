# Meta model roles in Tracii

Checked against https://dev.meta.ai/docs (models, structured output, voice, SAM and images pages) on 27 Oct 2026.
Live status measured with `scripts/check_models.py` on 29 Oct 2026; see `results/model_checks.json`.
Base URL `https://api.meta.ai/v1`, header `Authorization: Bearer $META_API_KEY`.

| Model | ID | Tracii feature | Endpoint used | Code | Status |
|---|---|---|---|---|---|
| Muse Spark 1.3 | `muse-spark-1.3` | Primary evidence-grounded explanation; scan Q&A; interprets SAM regions; **the four methodology agents** | `POST /chat/completions` with `response_format.json_schema` (strict) | `ai/investigator.py`, `ai/grounding.py`, `ai/agents.py` | **Live PASS** (1.9 s ping; agents 18–28 s each) |
| Muse Wonder | `muse-wonder-1.0` | "Deep investigation" button (`reasoning_effort: high`); **judge over the methodology agents** | `POST /chat/completions` | `investigator.explain(deep=True)`, `agents._judge` | **Live PASS** (1.7 s ping; judge 17–22 s) |
| Muse Image | `muse-image-1.0` | Optional report cover illustration labelled "AI-generated illustration. Not evidence." Off by default. | `POST /images/generations` (`b64_json`, png) | `api/main.py:report_image` | Implemented behind `ENABLE_REPORT_IMAGES=1`; UI button not yet added |
| Muse Voice Transcribe | `muse-voice-transcribe-1.0` | Hold-to-ask voice question → transcript → Spark Q&A | `POST /asr/transcribe` (multipart `request` JSON + `audio` WAV 16 kHz mono) | `meta_client.transcribe`, `app.js:toWav16k` | **Live PASS** on a 1 s silent WAV (empty transcript, as expected). The first live run found a duplicate-header bug the mocked tests had missed; fixed. Not yet tested with real speech in a browser. |
| SAM 3.1 | `sam-3.1` | Segment regions of uploaded visual incident evidence (e.g. an alert screenshot); Spark describes them separately | `POST /responses` (`input_text` + `input_image`) | `meta_client.segment`, `models.parse_sam_boxes` | **Live PASS**: on a 64×64 test image SAM returned the box x1=17,y1=17,x2=47,y2=47 for a square drawn at 17–47. UI not yet added. |
| Muse Glimmer | `meta/muse-glimmer-30b` on the NVIDIA API catalog (`https://integrate.api.nvidia.com/v1`, free developer credits) | Second independent reviewer of the agent judge; second opinion on single explanations | OpenAI-compatible `/chat/completions` | `models.open_weight_clients`, `agents._review` | **Live PASS** (29 Oct). Warm ping 1.3–2.1 s, but the first call took 242 s (cold start + retries) and the 13 kB judge prompt took **138 s** (agreed: track). So reviews run in the background (`GET /api/reviews/{id}`) with one 240 s attempt (`OPEN_WEIGHT_TIMEOUT`). Not on Baseten Model APIs. |
| Muse Spark Open | `meta-models/muse-spark-open-1026` on Baseten Model APIs (`https://inference.baseten.co/v1`) | Independent second opinion on a single explanation, and **independent reviewer of the agent judge** | OpenAI-compatible `/chat/completions` (strict JSON accepted) | `models.open_weight_clients`, `agents._review` | **Live PASS** (1.2 s ping; reviewer 10–17 s). The undated `meta-models/muse-spark-open` ID returns 403 for this key. |
| Muse Code | – | Development agent: at least one implementation or review task | – | `docs/MUSE_CODE_LOG.md` | To do |

Notes from the docs that shaped the design:
- The `-contributor` model IDs are cheaper, but prompts may be used for training. Tracii defaults to the Standard IDs because it sends third-party code and project metadata.
- Spark 1.3's audio input is degraded (the docs suggest 1.2 for audio). Tracii sends audio only to the dedicated transcription model.
- Chat Completions does not carry reasoning across turns. Tracii makes single-turn calls; a multi-turn Wonder agent would use `/responses`.
- With strict structured output, every object needs `additionalProperties: false` and full `required`. The schemas in `grounding.py` follow this.

## Multi-agent investigation (`ai/agents.py`)

| Agent | Standard method | Applies to | Model | Deterministic part |
|---|---|---|---|---|
| vuln_triage | CISA SSVC + FIRST EPSS + CISA KEV | known vulnerabilities | Spark 1.3 | SSVC outcome computed from the official CISA table (`ai/ssvc_cisa.csv`, pinned from CERTCC/SSVC); a KEV listing forces Exploitation = active; uncited decision points stay open and the outcome becomes a range |
| attack_mapping | MITRE ATT&CK | malicious indicators, version diffs | Spark 1.3 | closed list of technique IDs; unknown IDs dropped |
| integrity | SLSA provenance + OpenSSF Scorecard + npm publishing signals | all | Spark 1.3 | facts fetched from npm and Scorecard; labelled posture, never malware evidence |
| threat_model | STRIDE on the dependency path | all | Spark 1.3 | – |
| judge | reconciles the agents, lists agreements and conflicts | all | Wonder | falls back to the settled SSVC outcome |
| reviewers | same judge prompt, independent, in the background | all | Spark Open (Baseten), Glimmer (NVIDIA) | agreement with the judge is shown; they never override |

Measured on 29 Oct 2026 (live, Codespace):
| Finding | Agents | Judge | Spark Open | Total |
|---|---|---|---|---|
| lodash 4.17.20, GHSA-35jh-r3h4-6jhm (CVE-2021-23337) | 3 ok, 0 discarded claims; SSVC settled **track** (none / no / total / medium) | track | track (agrees) | 67 s (before the judge and reviewer ran in parallel) |
| fake-exfil fixture, TRACII-CHAIN-EXFIL | 3 ok; ATT&CK T1552, T1027, …; 2 uncited items discarded | insufficient_evidence | insufficient_evidence (agrees) | 43 s |
| minimist 1.2.5, GHSA-xvch-5gv4-984h (in the browser) | 3 ok; SSVC settled **track** | track | insufficient_evidence (**disagrees**, shown in the UI) | ~50 s |
