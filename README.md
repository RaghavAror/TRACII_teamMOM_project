# TRACII

**npm software-supply-chain security investigator**

Scan a project → find risks → show evidence → explain impact → recommend a fix → rescan to verify it.

Tracii reads a project's `package.json` + `package-lock.json`, checks exact installed versions against OSV
advisories, runs malicious-behaviour checks (GuardDog + Tracii's attack-chain rules) on prioritised packages
without installing them, traces how each flagged package is reached from your app, explains findings with
evidence-cited Meta Muse models, and verifies a proposed fix by re-resolving the lockfile and rescanning.

Three investigation views sit on top of the scan:
- **3D dependency graph** of *your* project (colour = scanner result, size = how many of your packages depend on it). Click a node to highlight every package above it, up to your app.
- **Attack replays** of four real npm incidents (event-stream, ua-parser-js, colors, node-ipc). Every step cites OSV, the npm registry or the original disclosure issue. If you use the package, the replay runs on your real path; otherwise it is a labelled simulation on your most depended-on package.
- **Multi-agent investigation**: agents for CISA SSVC + EPSS + KEV, MITRE ATT&CK, SLSA provenance + OpenSSF Scorecard and STRIDE run in parallel. A Muse Wonder judge reconciles them; Muse Spark Open (Baseten) and Muse Glimmer (NVIDIA API catalog, free credits) review independently in the background. Claims without evidence IDs are discarded.

> Results say what these checks detected. "No issue detected by these checks" is not a guarantee that a package is safe.

## Quick start (Codespaces or local)

```bash
bash scripts/setup_dev.sh          # venv, deps, osv-scanner binary, GuardDog (docker image, or its own venv without Docker), .env from template
# optional: put META_API_KEY, a Baseten key (Spark Open) and an NVIDIA key (Glimmer) in .env; see .env.example. Never commit it.
bash scripts/dev.sh                # API + UI on http://localhost:8000 (Codespaces: open forwarded port 8000)
```

Click **Demo project → Scan demo**, open a finding, then **Propose fix → Simulate fix and rescan**.
Then try **Play replay** under the 3D graph, and **Run investigation agents** on a finding (takes 40–70 s with live models).

```bash
cd backend && ../.venv/bin/python -m pytest -q          # offline test suite
.venv/bin/python scripts/evaluate.py --guarddog         # detector check on labelled fixtures → results/
.venv/bin/python scripts/check_models.py                # live probe of each configured model → results/model_checks.json
# measured model status and latencies: docs/MODELS.md
```

## CI gate, SARIF and SBOM

Add Tracii to any repo with a `package-lock.json`:

```yaml
# .github/workflows/tracii.yml
on: [pull_request, push]
permissions: { contents: read, security-events: write }   # security-events: SARIF upload
jobs:
  tracii:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RaghavAror/TRACII_teamMOM_project@main
        with:
          fail-on: high              # critical | high | medium | low | none
          mode: enforce              # observe = report only, never fail the job
          sbom-file: sbom.cdx.json   # optional CycloneDX 1.5 SBOM
```

The job writes a markdown report to the run summary, uploads SARIF to the **Security → Code scanning** tab
(each finding points at its entry in `package-lock.json`), and exits **0** pass · **1** blocking findings ·
**2** incomplete scan (OSV or the inventory could not run, so "no findings" would not mean anything). Unknown severities are
listed, never silently gated; use `fail-on-unknown: true` to gate them. All inputs: [action.yml](action.yml).

Same thing locally or in any other CI:

```bash
cd backend
../.venv/bin/python -m tracii scan --dir ../my-app --fail-on high --sarif tracii.sarif --sbom sbom.cdx.json
../.venv/bin/python -m tracii sbom --dir ../my-app -o sbom.cdx.json      # SBOM only: offline, no scan
```

In the web UI, every finished scan has **Export: SARIF · SBOM** links (`GET /api/scans/{id}/sarif`, `/sbom`, `/gate`).
The SBOM lists one component per name@version, with a purl, the SHA-512 from the lockfile, its scope (devDependencies
are `excluded`) and the resolved dependency graph. Only OSV advisories go into its `vulnerabilities`; malicious-behaviour
signals are detector output, not advisories, so they stay out of it.

## Layout

```
backend/tracii/
  intake/      github.py (URL → commit SHA → manifest files), npm_registry.py (safe tarball fetch)
  inventory/   lockfile.py (v1/v2/v3, nested resolution, direct/dev/install-script flags)
  detect/      osv.py (CLI | API), guarddog.py (Docker/offline), static_rules.py (attack chains)
  evidence/    schema.py (one Finding format), slicing.py (focused code slices)
  impact/      paths.py (shortest path per direct dependency, dev-only)
  diff/        version_diff.py (temporal security diff)
  ai/          meta_client.py, models.py (roles + honest status), grounding.py, investigator.py, threat_corpus.json
               agents.py (SSVC / ATT&CK / SLSA+Scorecard / STRIDE agents + judge), enrich.py (EPSS, KEV, npm provenance,
               Scorecard as citable evidence), ssvc_cisa.csv (official CISA table, pinned)
  replay/      scenarios.json (4 sourced incidents) + replay logic on the user's graph
  fix/         remediation.py (proposal → --package-lock-only --ignore-scripts → compare)
  export/      sarif.py (SARIF 2.1.0 for code scanning), sbom.py (CycloneDX 1.5 JSON)
  gate.py      CI pass/fail policy (enforce | observe, severity threshold, incomplete-scan rule) + markdown report
  cli.py       `python -m tracii scan | sbom` (used by action.yml)
  api/main.py  FastAPI routes (+ serves frontend/ in dev)
frontend/      static UI (no build step): app.js, graph3d.js (3d-force-graph from CDN + replays), agents-view.js
fixtures/      demo project (real lockfile) + INERT malicious-like test packages
docs/          ARCHITECTURE.md · PLAN.md · MODELS.md · CHAINVIZ_AUDIT.md · MUSE_CODE_LOG.md
```

## Deploy
- **API → Render:** `render.yaml` (Docker, `backend/Dockerfile`, build context = repo root). Set `META_API_KEY`
  and `ALLOWED_ORIGINS` in the Render dashboard.
- **UI → Vercel:** `vercel.json` serves `frontend/`. Set `window.TRACII_API` in `frontend/config.js` to the Render URL.

## Safety rules the code enforces
Never runs package lifecycle scripts · verifies tarball integrity and rejects links/traversal · keeps vulnerability
and malware categories separate · every AI claim must cite an evidence ID or it is discarded · package text is
treated as data, not instructions · fixes are proposed, never applied to your repo · "verified" only after a real rescan or model call.

## Credits
Started from an audit of [drPod/chainviz](https://github.com/drPod/chainviz) (MIT). See `docs/CHAINVIZ_AUDIT.md`
for what was kept. Uses [OSV-Scanner](https://github.com/google/osv-scanner) and [GuardDog](https://github.com/DataDog/guarddog) (both Apache-2.0).
3D view: [3d-force-graph](https://github.com/vasturiano/3d-force-graph) (MIT), loaded from jsDelivr, not vendored.
SSVC decision table from [CERTCC/SSVC](https://github.com/CERTCC/SSVC) (`backend/tracii/ai/ssvc_cisa.csv` records the commit).
Threat intel: [FIRST EPSS](https://www.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[OpenSSF Scorecard](https://scorecard.dev), [MITRE ATT&CK](https://attack.mitre.org). None of these needs an API key.
