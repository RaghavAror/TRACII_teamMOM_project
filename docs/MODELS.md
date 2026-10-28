# Meta model roles in Tracii

Checked against https://dev.meta.ai/docs (models, structured output, voice, SAM and images pages) on 27 Oct 2026.
Base URL `https://api.meta.ai/v1`, header `Authorization: Bearer $META_API_KEY`.

| Model | ID | Tracii feature | Endpoint used | Code | Status |
|---|---|---|---|---|---|
| Muse Spark 1.3 | `muse-spark-1.3` | Primary evidence-grounded explanation; scan Q&A; interprets SAM regions | `POST /chat/completions` with `response_format.json_schema` (strict) | `ai/investigator.py`, `ai/grounding.py` | Implemented + mocked tests; **live call pending key** |
| Muse Wonder | `muse-wonder-1.0` | "Deep investigation" button for one selected finding (`reasoning_effort: high`) | `POST /chat/completions` | `investigator.explain(deep=True)` | Implemented; preview model; **live call pending key** |
| Muse Image | `muse-image-1.0` | Optional report cover illustration labelled "AI-generated illustration. Not evidence." Off by default. | `POST /images/generations` (`b64_json`, png) | `api/main.py:report_image` | Implemented behind `ENABLE_REPORT_IMAGES=1`; UI button not yet added |
| Muse Voice Transcribe | `muse-voice-transcribe-1.0` | Hold-to-ask voice question → transcript → Spark Q&A | `POST /asr/transcribe` (multipart `request` JSON + `audio` WAV 16 kHz mono) | `meta_client.transcribe`, `app.js:toWav16k` | Implemented; **live call pending key** |
| SAM 3.1 | `sam-3.1` | Segment regions of uploaded visual incident evidence (e.g. an alert screenshot); Spark describes them separately | `POST /responses` (`input_text` + `input_image`) | `meta_client.segment`, `models.parse_sam_boxes` | API implemented; box parser tested on the documented format; UI not yet added |
| Muse Glimmer | env `GLIMMER_MODEL` | Optional independent second assessment of the same evidence; agreement shown, never overrides | OpenAI-compatible endpoint you host (vLLM/SGLang) | `models.open_weight_clients` | Adapter implemented + tested with a mock; **not run: no GPU endpoint** |
| Muse Spark Open | env `SPARK_OPEN_MODEL` | Same as Glimmer | OpenAI-compatible hosted endpoint | same | Adapter only; **not run** (816B-total / 42B-active MoE needs multi-GPU or a paid host) |
| Muse Code | – | Development agent: at least one implementation or review task | – | `docs/MUSE_CODE_LOG.md` | To do |

Notes from the docs that shaped the design:
- The `-contributor` model IDs are cheaper, but prompts may be used for training. Tracii defaults to the Standard IDs because it sends third-party code and project metadata.
- Spark 1.3's audio input is degraded (the docs suggest 1.2 for audio). Tracii sends audio only to the dedicated transcription model.
- Chat Completions does not carry reasoning across turns. Tracii makes single-turn calls; a multi-turn Wonder agent would use `/responses`.
- With strict structured output, every object needs `additionalProperties: false` and full `required`. The schemas in `grounding.py` follow this.
