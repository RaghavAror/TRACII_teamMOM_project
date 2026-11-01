"""Which model does what in Tracii, and its honest status.

Status values:
- not_configured: missing key/endpoint or feature flag; the feature degrades gracefully
- configured: credentials present, no call yet in this process
- verified: the last real call succeeded in this process (see meta_client.VERIFIED)
- failed: the last real call failed in this process (see meta_client.FAILED; short error shown)
Model IDs are overridable by env so a renamed/preview model needs no code change.
"""

from __future__ import annotations

import base64
import os
import re
import struct
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import httpx

from tracii.ai.meta_client import FAILED, VERIFIED, MetaClient, ModelUnavailable, OpenAICompatClient


@dataclass(frozen=True)
class ModelRole:
    key: str
    env_model: str
    default_model: str
    feature: str
    endpoint: str
    optional: bool
    flag: str | None = None   # extra env flag that must be "1" to enable

    @property
    def model_id(self) -> str:
        return os.environ.get(self.env_model, self.default_model)


ROLES = [
    ModelRole("investigator", "MODEL_INVESTIGATOR", "muse-spark-1.3",
              "Evidence-grounded explanation of each finding; voice/text Q&A", "/v1/chat/completions", False),
    ModelRole("deep", "MODEL_DEEP", "muse-wonder-1.0",
              "Deeper multi-step investigation for a user-selected complex finding (preview)",
              "/v1/chat/completions", True),
    ModelRole("image", "MODEL_IMAGE", "muse-image-1.0",
              "Optional, labelled illustrative cover image for incident reports (never evidence)",
              "/v1/images/generations", True, "ENABLE_REPORT_IMAGES"),
    ModelRole("voice", "MODEL_VOICE", "muse-voice-transcribe-1.0",
              "Transcribe a spoken question about findings (WAV) before grounded Q&A", "/v1/asr/transcribe", True),
    ModelRole("segment", "MODEL_SEGMENT", "sam-3.1",
              "Segment regions of uploaded visual incident evidence; Spark interprets crops separately",
              "/v1/responses", True),
]


def meta_client() -> MetaClient:
    return MetaClient()


def open_weight_clients() -> dict[str, tuple[OpenAICompatClient, str]]:
    """Optional independent assessors on OpenAI-compatible servers (vLLM/SGLang/hosted).

    Free hosted tiers can take minutes on long prompts (Glimmer on NVIDIA: ~140 s for the judge
    prompt), so they get one long attempt instead of retries that multiply the wait.
    """
    timeout = float(os.environ.get("OPEN_WEIGHT_TIMEOUT", "240"))
    out = {}
    for key in ("GLIMMER", "SPARK_OPEN"):
        base = os.environ.get(f"{key}_BASE_URL")
        model = os.environ.get(f"{key}_MODEL")
        if base and model:
            out[key.lower()] = (OpenAICompatClient(base, os.environ.get(f"{key}_API_KEY", "none"),
                                                   timeout=timeout, retries=0), model)
    return out


def _live_state(model: str | None, enabled: bool) -> tuple[str, str | None]:
    if not enabled or not model:
        return "not_configured", None
    ok_at, failed = VERIFIED.get(model), FAILED.get(model)
    if failed and (ok_at is None or failed[0] > ok_at):
        return "failed", failed[1]
    return ("verified", None) if ok_at else ("configured", None)


def status() -> list[dict]:
    has_key = bool(os.environ.get("META_API_KEY"))
    rows = []
    for r in ROLES:
        flag_off = r.flag is not None and os.environ.get(r.flag) != "1"
        st, err = _live_state(r.model_id, has_key and not flag_off)
        rows.append({"role": r.key, "model": r.model_id, "feature": r.feature, "endpoint": r.endpoint,
                     "optional": r.optional, "status": st, "error": err,
                     "note": f"off: set {r.flag}=1 to enable" if flag_off else None})
    for key, label in (("GLIMMER", "Muse Glimmer"), ("SPARK_OPEN", "Muse Spark Open")):
        model = os.environ.get(f"{key}_MODEL")
        st, err = _live_state(model, bool(os.environ.get(f"{key}_BASE_URL") and model))
        rows.append({"role": f"independent_{key.lower()}", "model": model or f"({label}: no endpoint)",
                     "feature": f"{label}: independent second assessment of the same evidence",
                     "endpoint": "OpenAI-compatible /v1/chat/completions (self-hosted or hosted)",
                     "optional": True, "status": st, "error": err})
    rows.append({"role": "dev_agent", "model": "Muse Code", "feature": "Development-time coding/review agent",
                 "endpoint": "n/a (used by the team, not by the running app)", "optional": False,
                 "status": "see docs/MUSE_CODE_LOG.md"})
    return rows


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


def live_check(open_weight_timeout: float = 25) -> list[dict]:
    """Minimal real request to every configured, enabled model (never Muse Image: billed per image).

    Updates VERIFIED / FAILED, so status() afterwards reflects what actually answered."""
    roles = {r.key: r.model_id for r in ROLES}
    c = MetaClient(retries=0, timeout=30)
    png = "data:image/png;base64," + base64.b64encode(tiny_png()).decode()
    jobs: dict[str, tuple[str, object]] = {}
    if c.configured:
        for key in ("investigator", "deep"):
            jobs[key] = (roles[key], lambda m=roles[key]: c.chat_json(
                m, "Reply with JSON.", 'Return {"ok": true}.', PING_SCHEMA, "ping", reasoning_effort="low"))
        jobs["voice"] = (roles["voice"], lambda: c.transcribe(silent_wav(), roles["voice"]))
        jobs["segment"] = (roles["segment"], lambda: c.segment(png, "square", roles["segment"]))
    for name, (client, model) in open_weight_clients().items():
        client._client.timeout = httpx.Timeout(open_weight_timeout)
        jobs[f"independent_{name}"] = (model, lambda cl=client, m=model: cl.chat_json(
            m, "Reply with JSON.", 'Return {"ok": true}.', PING_SCHEMA, "ping", strict=False))

    def run(item):
        role, (model, fn) = item
        t = time.perf_counter()
        try:
            fn()
            return {"role": role, "model": model, "ok": True, "latency_s": round(time.perf_counter() - t, 2)}
        except (ModelUnavailable, ValueError, KeyError) as exc:
            return {"role": role, "model": model, "ok": False, "latency_s": round(time.perf_counter() - t, 2),
                    "error": str(exc)[:200]}

    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(run, jobs.items()))


SAM_BOX = re.compile(r"<\|box;x1=(\d+);y1=(\d+);x2=(\d+);y2=(\d+);w=(\d+);h=(\d+)(?:;c=([\d.]+))?\|>")


def parse_sam_boxes(text: str) -> list[dict]:
    """Extract boxes from SAM 3.1 text output (masks ignored for the MVP)."""
    return [{"x1": int(m[0]), "y1": int(m[1]), "x2": int(m[2]), "y2": int(m[3]),
             "w": int(m[4]), "h": int(m[5]), "confidence": float(m[6]) if m[6] else None}
            for m in SAM_BOX.findall(text)]
