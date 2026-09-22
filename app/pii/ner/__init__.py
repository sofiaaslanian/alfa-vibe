"""NER client: HTTP to dedicated RuBERT service, or local lazy load."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from app.pii.contract import Finding
from app.pii.ner.mapper import map_entity, merge_adjacent_person

log = logging.getLogger("alfa.ner")


class NerClient:
    """
    NER for contextual PII (primarily PERSON / FIO).

    Enable with NER_ENABLED=1.
    - NER_URL=http://host:8090 → remote service
    - else local model (NER_LOCAL defaults to 1 when enabled and URL empty)
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 30.0,
        enabled: bool | None = None,
    ):
        self.base_url = (base_url if base_url is not None else os.getenv("NER_URL", "")).rstrip("/")
        self.timeout = float(os.getenv("NER_TIMEOUT", str(timeout)))
        env_enabled = os.getenv("NER_ENABLED", "0") == "1"
        self.enabled = env_enabled if enabled is None else enabled
        local_default = "1" if self.enabled and not self.base_url else "0"
        self.use_local = os.getenv("NER_LOCAL", local_default) == "1"
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
        return self.use_local

    def _ensure_local(self):
        if self._local is not None:
            return
        from app.pii.ner.model import PiiNerModel

        self._local = PiiNerModel()

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
                # Remote may already return canonical PERSON — accept both shapes
                out: list[Finding] = []
                for e in raw:
                    if e.get("type") == "PERSON" and "start" in e and "end" in e:
                        out.append(
                            Finding(
                                type="PERSON",
                                start=int(e["start"]),
                                end=int(e["end"]),
                                score=float(e.get("score", 0.0)),
                                detector=str(e.get("detector", "ml")),
                            )
                        )
                    else:
                        mapped = map_entity(e)
                        if mapped:
                            out.append(mapped)
                return merge_adjacent_person(out)

        if self.use_local:
            self._ensure_local()
            raw = self._local.predict(text)
        else:
            log.warning("NER enabled but neither NER_URL nor NER_LOCAL set")
            return []

        mapped = [m for e in raw if (m := map_entity(e)) is not None]
        return merge_adjacent_person(mapped)
