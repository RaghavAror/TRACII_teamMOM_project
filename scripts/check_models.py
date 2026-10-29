"""Probe every configured model with a minimal real request and record the outcome.

Usage (repo root, META_API_KEY exported):
  .venv/bin/python scripts/check_models.py            # Spark, Wonder, Voice, SAM, open-weight if configured
  .venv/bin/python scripts/check_models.py --image    # also Muse Image (billed per image)
Writes results/model_checks.json. Never prints the API key. A model is only
listed as working here if its call actually returned a usable response.
"""

from __future__ import annotations

import argparse
import base64
import json
import struct
import sys
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from tracii.ai.meta_client import MetaClient, ModelUnavailable  # noqa: E402
from tracii.ai.models import ROLES, open_weight_clients  # noqa: E402

PING_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["ok"],
               "properties": {"ok": {"type": "boolean"}}}


def silent_wav(seconds: float = 1.0, rate: int = 16000) -> bytes:
    n = int(seconds * rate)
    data = b"\x00\x00" * n
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt " +
            struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16) + b"data" + struct.pack("<I", len(data)) + data)


def tiny_png(w: int = 64, h: int = 64) -> bytes:
    raw = b"".join(b"\x00" + bytes([200 if 16 < x < 48 and 16 < y < 48 else 30 for x in range(w) for _ in range(3)]) for y in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def probe(name: str, model: str, fn) -> dict:
    t = time.perf_counter()
    try:
        detail = fn()
        return {"role": name, "model": model, "ok": True, "latency_s": round(time.perf_counter() - t, 2),
                "detail": str(detail)[:200]}
    except (ModelUnavailable, ValueError, KeyError) as exc:
        return {"role": name, "model": model, "ok": False, "latency_s": round(time.perf_counter() - t, 2),
                "error": str(exc)[:300]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", action="store_true")
    args = ap.parse_args()
    c = MetaClient(retries=0)
    roles = {r.key: r.model_id for r in ROLES}
    results = []
    if not c.configured:
        print("META_API_KEY not set: skipping Meta Model API probes")
    else:
        for key in ("investigator", "deep"):
            results.append(probe(key, roles[key], lambda m=roles[key]: c.chat_json(
                m, "Reply with JSON.", 'Return {"ok": true}.', PING_SCHEMA, "ping", reasoning_effort="low")))
        results.append(probe("voice", roles["voice"], lambda: repr(c.transcribe(silent_wav(), roles["voice"]))))
        png = "data:image/png;base64," + base64.b64encode(tiny_png()).decode()
        results.append(probe("segment", roles["segment"], lambda: c.segment(png, "square", roles["segment"])[:120]))
        if args.image:
            results.append(probe("image", roles["image"], lambda: f"{len(c.generate_image('a blue square', roles['image']))} b64 chars"))
    for name, (client, model) in open_weight_clients().items():
        results.append(probe(f"independent_{name}", model, lambda cl=client, m=model: cl.chat_json(
            m, "Reply with JSON.", 'Return {"ok": true}.', PING_SCHEMA, "ping", strict=False)))
    out = {"checked_at": datetime.now(timezone.utc).isoformat(), "results": results}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results/model_checks.json").write_text(json.dumps(out, indent=2))
    for r in results:
        print(("PASS " if r["ok"] else "FAIL ") + f"{r['role']:<22} {r['model']:<28} {r.get('latency_s')}s  "
              + (r.get("detail") or r.get("error", "")))
    if not results:
        print("Nothing configured; no model was called.")


if __name__ == "__main__":
    main()
