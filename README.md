# TRACII

**npm software-supply-chain security investigator** · Mind Over Model · Meta Global AI Developer Hackathon

Scan a project → find risks → show evidence → explain impact → recommend a fix → rescan to verify it.

Tracii reads a project's `package.json` + `package-lock.json`, checks exact installed versions against OSV
advisories, runs malicious-behaviour checks (GuardDog + Tracii's attack-chain rules) on prioritised packages
without installing them, traces how each flagged package is reached from your app, explains findings with
evidence-cited Meta Muse models, and verifies a proposed fix by re-resolving the lockfile and rescanning.

> Results say what these checks detected. "No issue detected by these checks" is not a guarantee that a package is safe.

## Quick start (Codespaces or local)

```bash
bash scripts/setup_dev.sh          # venv, deps, osv-scanner binary, GuardDog docker image, .env from template
# optional: put META_API_KEY in .env (never commit it)
bash scripts/dev.sh                # API + UI on http://localhost:8000 (Codespaces: open forwarded port 8000)
```

Click **Demo project → Scan demo**, open a finding, then **Propose fix → Simulate fix and rescan**.

```bash
cd backend && ../.venv/bin/python -m pytest -q          # offline test suite
.venv/bin/python scripts/evaluate.py --guarddog         # detector check on labelled fixtures → results/
.venv/bin/python scripts/check_models.py                # live probe of each configured model → results/
```

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
  fix/         remediation.py (proposal → --package-lock-only --ignore-scripts → compare)
  api/main.py  FastAPI routes (+ serves frontend/ in dev)
frontend/      static UI (no build step)
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
