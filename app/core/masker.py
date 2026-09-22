"""Маскирование и демаскирование с сохранением соответствий по payload_id."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from app.core.config import Config
from app.pii.contract import Finding
from app.pii.masker import apply_masks
from app.pii.pipeline import detect_pii

log = logging.getLogger("alfa.mask")


@dataclass
class MaskRecord:
    original: str
    masked: str
    findings: list[Finding] = field(default_factory=list)
    system: str = ""
    created_at: float = field(default_factory=time.time)


class LRUCache:
    """Потокобезопасный LRU-кэш payload_id -> MaskRecord."""

    def __init__(self, maxsize: int = 100_000, ttl: int = 3600):
        self._lock = threading.Lock()
        self._store: OrderedDict[str, MaskRecord] = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl

    def get(self, key: str) -> Optional[MaskRecord]:
        with self._lock:
            rec = self._store.get(key)
            if rec is None:
                return None
            if time.time() - rec.created_at > self._ttl:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return rec

    def set(self, key: str, value: MaskRecord) -> None:
        with self._lock:
            self._store[key] = value
            self._store.move_to_end(key)
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)


class Masker:
    """Основной модуль маскирования/демаскирования."""

    def __init__(self, config: Config, store: Optional[LRUCache] = None):
        self.config = config
        self.store = store or LRUCache()

    def _token_style(self, system: Optional[str]) -> bool:
        if system and system in self.config.systems:
            return self.config.systems[system].mask_style == "token"
        return False

    def detect(self, text: str, system: Optional[str] = None) -> list[Finding]:
        findings = detect_pii(text)
        if system and system in self.config.systems:
            allowed = self.config.systems[system].pd_types
            if allowed:
                findings = [f for f in findings if f.type in allowed]
        elif self.config.default_pd_types:
            allowed = set(self.config.default_pd_types)
            findings = [f for f in findings if f.type in allowed]
        return findings

    def mask(self, text: str, system: Optional[str] = None) -> str:
        findings = self.detect(text, system)
        return apply_masks(text, findings, token_style=self._token_style(system))

    def process(self, payload: str, payload_id: str, system: Optional[str] = None) -> str:
        """Первый запрос с payload_id — mask; повтор с тем же id — demask original."""
        rec = self.store.get(payload_id)
        if rec is None:
            findings = self.detect(payload, system)
            masked = apply_masks(payload, findings, token_style=self._token_style(system))
            rec = MaskRecord(
                original=payload,
                masked=masked,
                findings=findings,
                system=system or "",
            )
            self.store.set(payload_id, rec)
            log.info("mask payload_id=%s findings=%d", payload_id, len(findings))
            return masked

        # If client sends original again — return same mask (retry)
        if payload == rec.original:
            return rec.masked
        # If client sends masked (or anything else after first) — demask
        log.info("demask payload_id=%s", payload_id)
        return rec.original
