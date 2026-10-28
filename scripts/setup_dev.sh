#!/usr/bin/env bash
# One-time dev setup (Codespaces or local). Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r backend/requirements-dev.txt
# OSV-Scanner binary (optional: Tracii falls back to the OSV API)
if ! command -v osv-scanner >/dev/null; then
  mkdir -p .venv/bin
  curl -fsSL -o .venv/bin/osv-scanner \
    https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 && chmod +x .venv/bin/osv-scanner || true
fi
# GuardDog via Docker (avoids Python-version conflicts with its Semgrep dependency)
if command -v docker >/dev/null; then docker pull -q ghcr.io/datadog/guarddog:latest || true; fi
[ -f .env ] || cp .env.example .env
echo "Setup done. Run: bash scripts/dev.sh"
