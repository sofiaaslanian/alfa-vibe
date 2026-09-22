"""NER client: HTTP to dedicated RuBERT service, or optional local lazy load."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from app.pii.contract import Finding
from app.pii.ner.mapper import map_entity, merge_adjacent_person

log = logging.getLogger("alfa.ner")

DEFAULT_MODEL = "redmadrobot-rnd/rubert-base-pii-ner"


class NerClient:
    """Calls external NER service. If NER_URL empty and NER_LOCAL=1, loads model locally."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 5.0,
        enabled: bool | None = None,
    ):
        self.base_url = (base_url or os.getenv("NER_URL", "")).rstrip("/")
        self.timeout = timeout
        env_enabled = os.getenv("NER_ENABLED", "0") == "1"
        self.enabled = env_enabled if enabled is None else enabled
        self._local = None

    def available(self) -> bool:
        if not self.enabled:
            return False
        if self.base_url:
            try:
                with httpx.Client(timeout=2.0) as client:
                    r = client.get(f"{self.base_url}/health")
                    return r.status_code == 200
            except Exception:
                return False
        return os.getenv("NER_LOCAL", "0") == "1"

    def _ensure_local(self):
        if self._local is not None:
            return
        from transformers import pipeline  # lazy heavy import

        log.info("Loading local NER model %s", DEFAULT_MODEL)
        self._local = pipeline(
            "token-classification",
            model=os.getenv("NER_MODEL", DEFAULT_MODEL),
            aggregation_strategy="simple",
        )

    def detect(self, text: str) -> list[Finding]:
        if not self.enabled:
            return []

        raw: list[dict[str, Any]]
        if self.base_url:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/detect", json={"text": text})
                resp.raise_for_status()
                data = resp.json()
                raw = data.get("entities", data if isinstance(data, list) else [])
        elif os.getenv("NER_LOCAL", "0") == "1":
            self._ensure_local()
            raw = [
                {
                    "entity_group": e["entity_group"],
                    "start": e["start"],
                    "end": e["end"],
                    "score": float(e["score"]),
                }
                for e in self._local(text)
            ]
        else:
            return []

        mapped = [m for e in raw if (m := map_entity(e)) is not None]
        return merge_adjacent_person(mapped)
