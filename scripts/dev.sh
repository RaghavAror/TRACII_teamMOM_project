#!/usr/bin/env bash
# Start API + UI on :8000. Loads .env if present (values are never printed).
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then set -a; . ./.env; set +a; fi
export PATH="$PWD/.venv/bin:$PATH"
cd backend
exec uvicorn tracii.api.main:app --host 0.0.0.0 --port "${PORT:-8000}" --reload
