"""Thin HTTP clients for the Meta Model API and OpenAI-compatible open-weight endpoints.

Schemas follow https://dev.meta.ai/docs (checked 2026-10-27):
- POST /v1/chat/completions, structured output via response_format.json_schema;
  JSON arrives as a string in choices[0].message.content
- POST /v1/asr/transcribe, multipart parts `request` (JSON) + `audio` (WAV, mono 16/24 kHz, <=10 min, <=32 MB)
- POST /v1/images/generations {model, prompt, n, response_format}
- POST /v1/responses with model sam-3.1, content [input_text, input_image]
The API key never leaves the backend and is never logged.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

META_BASE_URL = os.environ.get("META_API_BASE_URL", "https://api.meta.ai/v1")
RETRY_STATUS = {429, 500, 502, 503, 504}

# model id -> unix time of last successful call in this process. Used only for
# the status page; a model is "verified" only after a real call succeeded.
VERIFIED: dict[str, float] = {}


class ModelUnavailable(RuntimeError):
    """Model not configured, unreachable, rate-limited, or returned unusable output."""


class OpenAICompatClient:
    """Works for api.meta.ai and for self-hosted vLLM/SGLang (OpenAI-compatible) servers."""

    def __init__(self, base_url: str, api_key: str | None, *, timeout: float = 90,
                 client: httpx.Client | None = None, retries: int = 2):
        self.base_url = base_url.rstrip("/")
        self._key = api_key
        self._client = client or httpx.Client(timeout=timeout)
        self.retries = retries

    @property
    def configured(self) -> bool:
        return bool(self._key) and bool(self.base_url)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}"} if self._key else {}

    def _post(self, path: str, **kwargs: Any) -> httpx.Response:
        if not self.configured:
            raise ModelUnavailable("model endpoint not configured")
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                resp = self._client.post(f"{self.base_url}{path}", headers=self._headers(), **kwargs)
            except httpx.HTTPError as exc:
                last = exc
            else:
                if resp.status_code < 400:
                    return resp
                if resp.status_code not in RETRY_STATUS:
                    # error body may echo input; keep only the status + short message
                    raise ModelUnavailable(f"HTTP {resp.status_code}: {resp.text[:200]}")
                last = ModelUnavailable(f"HTTP {resp.status_code}")
            time.sleep(min(2 ** attempt, 8))
        raise ModelUnavailable(f"request failed after retries: {last}")

    def chat_json(self, model: str, system: str, user: str, schema: dict, schema_name: str,
                  reasoning_effort: str | None = None, strict: bool = True,
                  image_data_url: str | None = None) -> dict:
        content: Any = user
        if image_data_url:
            content = [{"type": "text", "text": user}, {"type": "image_url", "image_url": {"url": image_data_url}}]
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": schema_name, "schema": schema, "strict": strict}},
        }
        if reasoning_effort:
            body["reasoning_effort"] = reasoning_effort
        resp = self._post("/chat/completions", json=body)
        try:
            content = resp.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content) if isinstance(content, str) else content
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelUnavailable(f"unparseable model output: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ModelUnavailable("model output is not a JSON object")
        VERIFIED[model] = time.time()
        return parsed


class MetaClient(OpenAICompatClient):
    def __init__(self, api_key: str | None = None, **kwargs: Any):
        super().__init__(META_BASE_URL, api_key if api_key is not None else os.environ.get("META_API_KEY"), **kwargs)

    def transcribe(self, wav: bytes, model: str = "muse-voice-transcribe-1.0") -> str:
        if not wav.startswith(b"RIFF") or wav[8:12] != b"WAVE":
            raise ValueError("audio must be a WAV file (mono PCM, 16 or 24 kHz)")
        if len(wav) > 32 * 1024 * 1024:
            raise ValueError("audio exceeds 32 MB")
        request = json.dumps({"model": model, "audioEncoding": "WAV", "mode": "PUSH_TO_TALK"})
        resp = self._post("/asr/transcribe",
                          files={"request": (None, request, "application/json"),
                                 "audio": ("question.wav", wav, "audio/wav")},
                          headers={**self._headers(), "Accept": "application/json"})
        text = resp.json().get("transcript", "")
        VERIFIED[model] = time.time()
        return text

    def generate_image(self, prompt: str, model: str = "muse-image-1.0") -> str:
        resp = self._post("/images/generations",
                          json={"model": model, "prompt": prompt, "n": 1, "response_format": "b64_json",
                                "output_format": "png", "size": "1536x1024"})
        data = resp.json().get("data") or []
        if not data or not data[0].get("b64_json"):
            raise ModelUnavailable("no image returned")
        VERIFIED[model] = time.time()
        return data[0]["b64_json"]

    def segment(self, image_data_url: str, prompt: str, model: str = "sam-3.1") -> str:
        """Returns SAM's raw box/mask text; parse with tracii.ai.sam.parse_boxes."""
        body = {"model": model, "metadata": {"include_confidence": "true"},
                "input": [{"role": "user", "content": [
                    {"type": "input_text", "text": prompt},
                    {"type": "input_image", "image_url": image_data_url}]}]}
        resp = self._post("/responses", json=body)
        data = resp.json()
        texts = [c.get("text", "") for item in data.get("output") or [] for c in item.get("content") or []
                 if isinstance(c, dict)]
        VERIFIED[model] = time.time()
        return "\n".join(t for t in texts if t)
