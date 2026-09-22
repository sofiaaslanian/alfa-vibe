"""Local RuBERT PII NER wrapper with chunking."""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("alfa.ner.model")

DEFAULT_MODEL = "redmadrobot-rnd/rubert-base-pii-ner"
MAX_LENGTH = int(os.getenv("NER_MAX_LENGTH", "512"))
STRIDE = int(os.getenv("NER_STRIDE", "128"))


class PiiNerModel:
    def __init__(self, model_name: str | None = None):
        from transformers import pipeline

        name = model_name or os.getenv("NER_MODEL", DEFAULT_MODEL)
        log.info("Loading NER model %s", name)
        self.model_name = name
        self._pipe = pipeline(
            "token-classification",
            model=name,
            aggregation_strategy="simple",
            device=-1,  # CPU; set NER_DEVICE=0 for GPU
        )
        device = os.getenv("NER_DEVICE")
        if device is not None and device != "-1":
            # recreate on requested device if user set it
            self._pipe = pipeline(
                "token-classification",
                model=name,
                aggregation_strategy="simple",
                device=int(device),
            )

    def predict(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        # Short texts: single pass
        if len(text) < MAX_LENGTH * 3:
            return list(self._pipe(text))

        # Sliding window by characters (approx); good enough for hackathon MVP
        entities: list[dict[str, Any]] = []
        step = max(MAX_LENGTH - STRIDE, 1) * 2  # ~chars heuristic
        window = MAX_LENGTH * 3
        start = 0
        while start < len(text):
            chunk = text[start : start + window]
            for e in self._pipe(chunk):
                entities.append(
                    {
                        "entity_group": e["entity_group"],
                        "start": int(e["start"]) + start,
                        "end": int(e["end"]) + start,
                        "score": float(e["score"]),
                    }
                )
            if start + window >= len(text):
                break
            start += step

        # Dedup exact spans
        seen: set[tuple] = set()
        unique = []
        for e in entities:
            key = (e["entity_group"], e["start"], e["end"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(e)
        return unique
