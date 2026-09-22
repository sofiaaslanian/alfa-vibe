"""RuBERT NER for FIO: local model + optional HTTP client."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from app.pii.detect import Finding

log = logging.getLogger("alfa.ner")

DEFAULT_MODEL = "redmadrobot-rnd/rubert-base-pii-ner"
MAX_LENGTH = int(os.getenv("NER_MAX_LENGTH", "512"))
STRIDE = int(os.getenv("NER_STRIDE", "128"))

LABEL_MAP = {
    "FIRST_NAME": "PERSON",
    "LAST_NAME": "PERSON",
    "MIDDLE_NAME": "PERSON",
    "PER": "PERSON",
    "PERSON": "PERSON",
}


def _normalize_label(label: str) -> str:
    label = (label or "").strip()
    if label.startswith(("B-", "I-", "S-", "E-")):
        label = label.split("-", 1)[1]
    return label.upper().replace(" ", "_")


def map_entity(entity: dict) -> Finding | None:
    raw = entity.get("entity_group") or entity.get("entity") or entity.get("type")
    label = _normalize_label(str(raw))
    if label not in LABEL_MAP:
        return None
    return Finding(
        type=LABEL_MAP[label],
        start=int(entity["start"]),
        end=int(entity["end"]),
        score=float(entity.get("score", 0.0)),
        detector="ml",
    )


def merge_adjacent_person(findings: list[Finding], max_gap: int = 3) -> list[Finding]:
    persons = sorted([f for f in findings if f.type == "PERSON"], key=lambda f: f.start)
    others = [f for f in findings if f.type != "PERSON"]
    if not persons:
        return findings
    merged: list[Finding] = []
    cur = persons[0]
    for nxt in persons[1:]:
        if nxt.start - cur.end <= max_gap:
            cur = Finding("PERSON", cur.start, max(cur.end, nxt.end), min(cur.score, nxt.score), "ml")
        else:
            merged.append(cur)
            cur = nxt
    merged.append(cur)
    return others + merged


class PiiNerModel:
    def __init__(self, model_name: str | None = None):
        from transformers import pipeline

        name = model_name or os.getenv("NER_MODEL", DEFAULT_MODEL)
        log.info("Loading NER model %s", name)
        device = int(os.getenv("NER_DEVICE", "-1"))
        self.model_name = name
        offline = os.getenv("HF_HUB_OFFLINE", "0") == "1" or os.getenv("TRANSFORMERS_OFFLINE", "0") == "1"
        # Prefer cached weights (RU servers often have no HF access).
        try:
            self._pipe = pipeline(
                "token-classification",
                model=name,
                aggregation_strategy="simple",
                device=device,
                model_kwargs={"local_files_only": True},
            )
        except Exception:
            if offline:
                raise
            log.warning("NER cache miss — downloading %s", name)
            self._pipe = pipeline(
                "token-classification",
                model=name,
                aggregation_strategy="simple",
                device=device,
            )

    def predict(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        if len(text) < MAX_LENGTH * 3:
            return list(self._pipe(text))
        entities: list[dict[str, Any]] = []
        step = max(MAX_LENGTH - STRIDE, 1) * 2
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
        seen: set[tuple] = set()
        unique = []
        for e in entities:
            key = (e["entity_group"], e["start"], e["end"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(e)
        return unique


class NerClient:
    """NER_ENABLED=1; NER_URL for remote, else local RuBERT."""

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
        self._local: PiiNerModel | None = None

    def _ensure_local(self):
        if self._local is None:
            self._local = PiiNerModel()

    def detect(self, text: str) -> list[Finding]:
        if not self.enabled:
            return []
        if self.base_url:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/detect", json={"text": text})
                resp.raise_for_status()
                data = resp.json()
                raw = data.get("entities", data if isinstance(data, list) else [])
            out: list[Finding] = []
            for e in raw:
                if e.get("type") == "PERSON" and "start" in e:
                    out.append(
                        Finding("PERSON", int(e["start"]), int(e["end"]), float(e.get("score", 0)), "ml")
                    )
                else:
                    mapped = map_entity(e)
                    if mapped:
                        out.append(mapped)
            return merge_adjacent_person(out)
        if not self.use_local:
            return []
        self._ensure_local()
        raw = self._local.predict(text)
        return merge_adjacent_person([m for e in raw if (m := map_entity(e))])
