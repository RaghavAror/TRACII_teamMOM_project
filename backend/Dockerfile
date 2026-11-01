# Tracii API + web UI in one service (Render Docker runtime, or any container host). Build context: repository root.
#   docker build -f backend/Dockerfile -t tracii .
#   docker run -p 8000:8000 --env-file .env tracii      -> http://localhost:8000
# The UI is served from the same origin as the API (no CORS, no API URL to configure).
# For a separate static frontend (vercel.json), set SERVE_FRONTEND=0 and ALLOWED_ORIGINS.
FROM python:3.12-slim

# Node/npm only for `npm install --package-lock-only --ignore-scripts` (fix simulation).
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# OSV-Scanner (Apache-2.0) static binary; pinned. Falls back to the OSV API if absent.
ARG OSV_SCANNER_VERSION=2.7.0
RUN curl -fsSL -o /usr/local/bin/osv-scanner \
      https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt \
    && pip install --no-cache-dir guarddog==3.2.0
COPY backend ./backend
COPY fixtures ./fixtures
COPY frontend ./frontend

# GuardDog refreshes a typosquatting cache inside its own package dir at runtime.
RUN useradd --create-home tracii && chown -R tracii /app \
    && chown -R tracii "$(python -c 'import guarddog, os; print(os.path.dirname(guarddog.__file__))')/analyzer/metadata/resources"
USER tracii
ENV PYTHONUNBUFFERED=1 SERVE_FRONTEND=1 GUARDDOG_MODE=local NPM_RESOLVER=local \
    npm_config_ignore_scripts=true PORT=8000
WORKDIR /app/backend
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS "http://localhost:${PORT}/api/health" || exit 1
# --proxy-headers: behind Render's proxy, the per-client rate limit must see the real client IP
CMD uvicorn tracii.api.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips="*"
