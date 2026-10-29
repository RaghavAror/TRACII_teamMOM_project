# Tracii hackathon plan (27 Oct – 3 Nov 2026)

Status key: ✅ done in baseline · 🟡 partial · ⬜ not started

## Milestones and acceptance criteria

### M0 · Baseline (27 Oct) ✅
- [x] Repo layout, FastAPI backend, static UI, finding schema, 51 offline tests.
- [x] Live end-to-end run on `fixtures/projects/vulnerable-demo` (see "Recorded results" below).
**Accept:** `pytest` is green; `bash scripts/dev.sh` serves the UI at :8000; a demo scan completes.

### M1 · Intake + inventory hardening (28 Oct) 🟡
- [x] GitHub URL → commit SHA pinning; upload; fixture.
- [ ] Test against 5 real public repos (small app, monorepo subdir, lockfile v1, missing lockfile, private/404).
- [ ] Show the SHA prominently and link to the commit on GitHub.
**Accept:** each repo either scans or fails with a clear 4xx message; no scan runs without a lockfile; the SHA is shown.

### M2 · Detection channels (28–29 Oct) 🟡
- [x] OSV (CLI and API agree: 21/21 on the demo), GuardDog (Docker), Tracii chain rules.
- [ ] Map CVSS vectors to severity when `database_specific.severity` is missing (currently `unknown`).
- [ ] Prioritisation tuning: always deep-scan packages in the *path* of a vuln finding plus every `hasInstallScript`.
- [ ] Optional: OpenSSF Scorecard as a `repository_posture` category (only if M3–M5 are stable).
**Accept:** summary counts stay separated per category; every check appears in "What was checked" with its true status.

### M3 · Grounded AI (29–30 Oct) 🟡 — needs `META_API_KEY`
- [x] Spark/Wonder clients, strict schema, evidence-ID validation, injection fencing, deterministic fallback.
- [ ] Run `scripts/check_models.py`; commit `results/model_checks.json` with the real PASS/FAIL.
- [ ] Tune prompts on 3 findings (1 CVE, 1 chain, 1 prompt-injection fixture); record discarded-claim counts.
- [ ] Voice Q&A tested end to end in Chrome.
**Accept:** for each tested finding, every displayed claim links to an existing evidence ID; with the key removed the UI still works and labels the output as "AI unavailable".

### M4 · Impact + fix + verified rescan (30–31 Oct) ✅/🟡
- [x] Shortest paths, dev-only flag, sibling-aware fix target, `overrides` for transitive deps.
- [x] Real rescan: lodash 4.17.20 → 4.18.0 cleared 5/5 lodash advisories (`verified_fixed`).
- [ ] "Fix all for this direct dependency" (e.g. express 4.17.1 → latest 4.x) with combined rescan.
- [ ] Clickable path nodes highlight the subgraph (currently they filter the table).
**Accept:** the status reads `verified_fixed` only when the rescan ran; `unverified` is shown when the resolver is unavailable (covered by a test).

### M5 · Temporal diff + attack-chain demo (31 Oct – 1 Nov) 🟡
- [x] `/api/diff` on real tarballs (core-js 2.5.7 → 2.6.12 surfaces the added postinstall).
- [ ] Feed diff findings into the AI explainer; add a "diff this package against the previous release" button on each finding.
- [ ] Expand labelled samples beyond our 4 self-written fixtures (see Risk 3).
**Accept:** the diff shows install-script, host, capability and dependency changes with file:line evidence and the "clue, not proof" note.

### M6 · Deploy + demo (1–3 Nov) ⬜
- [ ] Render (Docker) API + Vercel UI; set `config.js` to the Render URL and `ALLOWED_ORIGINS` to the Vercel URL.
- [ ] Optional media: Muse Image cover (flagged), SAM evidence segmentation.
- [ ] Muse Code: at least one logged implementation or review task (`docs/MUSE_CODE_LOG.md`).
- [ ] 3-minute demo script; a backup recording of a local run.
**Accept:** the public URL completes a demo scan in under 60 s; the model-status dialog matches `results/model_checks.json`.

### M7 · Graph, replays, multi-agent (29 Oct) ✅ — live models
- [x] 3D dependency graph of the user's project (`/api/scans/{id}/graph` with per-node findings, dependents count, dev-only flag).
- [x] Attack replays: 4 sourced incidents, `in_project` vs labelled `simulated` mode, blast-radius waves (`/api/replays`, `/api/scans/{id}/replays/{rid}`).
- [x] Methodology agents + judge + Spark Open reviewer (`/api/scans/{id}/findings/{fid}/agents`); SSVC from the official CISA table.
- [x] Glimmer via the NVIDIA API catalog (free credits). Reviews moved to the background because a free tier takes ~140 s on the judge prompt.
- [ ] Voice Q&A with real speech in Chrome; SAM upload UI.
**Accept:** browser run without console errors; every agent claim cites an existing evidence ID; the replay says SIMULATION when the package is absent.

## Top 3 technical risks

| # | Risk | Mitigation (in this baseline) |
|---|---|---|
| 1 | **False positives / false confidence.** chainviz matched CVEs by name only; GuardDog flagged `process.env` reads in a benign API client; malware rules over-fire on SDKs. | Exact-version OSV matching; chain rules require a corroborating step (encode / sensitive file / install-time); confidence + limitations on every finding; categories never merged. |
| 2 | **Unsafe handling of untrusted packages** (install scripts, zip-slip, symlinks, prompt injection). | No install anywhere; integrity-verified in-memory extraction; GuardDog offline in Docker; `--ignore-scripts` resolution; injection fencing + claim-ID validation, all with tests. |
| 3 | **Unproven claims at judging** (model availability, detection quality). | Model status reports `verified` only after a real call; `check_models.py` and `evaluate.py` write measured JSON; our fixtures are labelled as self-written regression checks, not a benchmark. Next step: add statically analysed real samples from OSSF malicious-packages reports. |

## Recorded results (27 Oct 2026, Codespace: 2 vCPU / 7 GB)

| Check | Result |
|---|---|
| Unit tests | 51 passed (offline, mocked network) |
| Demo scan, live, deep limit 6 | 53 packages, 21 known-vuln findings (1 critical, 7 high, 7 medium, 6 low), 21.3 s |
| OSV CLI vs API on demo | identical 21 findings |
| GuardDog on demo deps (after manifest fix) | 0 threat findings, 4 info capability findings |
| Fix lodash 4.17.20 → 4.18.0 + real rescan | 5 fixed, 0 new, `verified_fixed`, 20.4 s |
| `evaluate.py --guarddog`, 4 self-written fixtures | Tracii static 3/3 malicious flagged, 0/1 benign FP; GuardDog (≥medium) 1/3, 0/1 FP. **Circular: fixtures written with the rules in mind. Do not quote as a detection rate.** |
| Meta models (29 Oct) | **5/5 live PASS** with `scripts/check_models.py`: Spark 1.3 1.9 s, Wonder 1.7 s, Voice 1.3 s, SAM 3.1 1.2 s, Spark Open on Baseten 1.2 s. Muse Image not called (billed per image). |
| Bugs found by the first live run (29 Oct) | Voice transcription crashed before sending (`headers` passed twice); the check script's test PNG generator had a type error. Both fixed; the mocked tests had missed both. |
| Multi-agent, live (29 Oct) | lodash CVE-2021-23337: SSVC **track**, judge track, Spark Open agrees (67 s, sequential judge). fake-exfil fixture: ATT&CK T1552/T1027, judge + Spark Open insufficient_evidence (43 s). minimist in the browser: judge track, Spark Open **disagrees** (shown). |
| Replay detection check (29 Oct) | Malicious versions of all 4 incidents have been removed from npm, so Tracii could not be tested on the real payloads. Measured instead: `/api/diff` node-ipc 10.1.0 → 11.0.0 reports `peacenotwar@^9.1.3` added (1 low finding, no install script / host / capability change). |
| Browser end-to-end (29 Oct, headless Chromium, SwiftShader WebGL) | Demo scan → 3D graph (53 packages, 89 edges) → event-stream replay (simulated on statuses@1.5.0) → agents on minimist; upload with colors@1.4.1 → in-project replay. 0 console errors. |
| Glimmer live (29 Oct) | NVIDIA `meta/muse-glimmer-30b`: ping PASS (2 s warm, 242 s on first call); judge prompt 138 s, priority track = Wonder judge. Before the fix, a timed-out Glimmer stretched one investigation to 303 s; now the judge answers without waiting. One background run returned an empty answer; with an explicit 16k output budget, 3/3 later runs answered (135 s, 144 s, 201 s; all track = judge). Browser: judge at 52 s, Spark Open agrees at 52 s, Glimmer agrees at 233 s, 0 console errors. Also fixed: review rows rendered as "[object HTMLDivElement]". |
| Unit tests (29 Oct) | 65 passed (+1: deferred reviews); earlier 64 (13 new: SSVC table, citation validation, KEV override, enrichment failure, reviewer, graph overlay, replays, endpoints) |
