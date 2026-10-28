"""Which model does what in Tracii, and its honest status.

Status values:
- not_configured: missing key/endpoint or feature flag; the feature degrades gracefully
- configured: credentials present, no successful call yet in this process
- verified: a real call succeeded in this process (see meta_client.VERIFIED)
Model IDs are overridable by env so a renamed/preview model needs no code change.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from tracii.ai.meta_client import VERIFIED, MetaClient, OpenAICompatClient


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
    """Optional independent assessors on OpenAI-compatible servers (vLLM/SGLang/hosted)."""
    out = {}
    for key in ("GLIMMER", "SPARK_OPEN"):
        base = os.environ.get(f"{key}_BASE_URL")
        model = os.environ.get(f"{key}_MODEL")
        if base and model:
            out[key.lower()] = (OpenAICompatClient(base, os.environ.get(f"{key}_API_KEY", "none")), model)
    return out


def status() -> list[dict]:
    has_key = bool(os.environ.get("META_API_KEY"))
    rows = []
    for r in ROLES:
        enabled = has_key and (r.flag is None or os.environ.get(r.flag) == "1")
        st = "verified" if r.model_id in VERIFIED else ("configured" if enabled else "not_configured")
        rows.append({"role": r.key, "model": r.model_id, "feature": r.feature, "endpoint": r.endpoint,
                     "optional": r.optional, "status": st})
    for key, label in (("GLIMMER", "Muse Glimmer"), ("SPARK_OPEN", "Muse Spark Open")):
        model = os.environ.get(f"{key}_MODEL")
        configured = bool(os.environ.get(f"{key}_BASE_URL") and model)
        rows.append({"role": f"independent_{key.lower()}", "model": model or f"({label}: no endpoint)",
                     "feature": f"{label}: independent second assessment of the same evidence",
                     "endpoint": "OpenAI-compatible /v1/chat/completions (self-hosted or hosted)",
                     "optional": True,
                     "status": "verified" if model in VERIFIED else ("configured" if configured else "not_configured")})
    rows.append({"role": "dev_agent", "model": "Muse Code", "feature": "Development-time coding/review agent",
                 "endpoint": "n/a (used by the team, not by the running app)", "optional": False,
                 "status": "see docs/MUSE_CODE_LOG.md"})
    return rows


SAM_BOX = re.compile(r"<\|box;x1=(\d+);y1=(\d+);x2=(\d+);y2=(\d+);w=(\d+);h=(\d+)(?:;c=([\d.]+))?\|>")


def parse_sam_boxes(text: str) -> list[dict]:
    """Extract boxes from SAM 3.1 text output (masks ignored for the MVP)."""
    return [{"x1": int(m[0]), "y1": int(m[1]), "x2": int(m[2]), "y2": int(m[3]),
             "w": int(m[4]), "h": int(m[5]), "confidence": float(m[6]) if m[6] else None}
            for m in SAM_BOX.findall(text)]
