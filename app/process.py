"""Process service: detect → mask → shared state with HMAC retries/409/410."""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

from app.config import Config
from app.crypto_util import decrypt, encrypt, hmac_hex
from app.masking import apply_dev_redact, apply_scoped_tokens, restore_scoped_tokens
from app.pii.detect import Finding, detect_pii
from app.state import OperationState, StateStore

log = logging.getLogger("alfa.process")

NS_AUTOTEST = "autotest"
NS_PROXY = "proxy"

# ML context flow is needed when any context-defined type is enabled.
CONTEXT_TYPES = {
    "PERSON",
    "PERSON_NAME",
    "PLACE_OF_BIRTH",
    "CITIZENSHIP",
    "PASSPORT_ISSUER",
    "ADDRESS",
    "CARDHOLDER_NAME",
}


class ProcessError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


class ProcessService:
    def __init__(self, config: Config, store: StateStore):
        self.config = config
        self.store = store

    def _allowed_types(self, system: Optional[str]) -> set[str] | None:
        allowed: list[str] | None = None
        if system and system in self.config.systems:
            allowed = self.config.systems[system].pd_types or None
        if not allowed:
            allowed = self.config.default_pd_types or None
        return set(allowed) if allowed else None

    def _combo_policy(self, system: Optional[str]) -> dict[str, list[str]]:
        if system and system in self.config.systems:
            sys_combo = self.config.systems[system].combo_require
            if sys_combo:
                return sys_combo
        return self.config.combo_require or {}

    @staticmethod
    def _apply_combo(
        findings: list[Finding], combo: dict[str, list[str]]
    ) -> list[Finding]:
        """Drop types that require co-occurring companions (e.g. PIN needs CARD)."""
        if not combo:
            return findings
        present = {f.type for f in findings if getattr(f, "decision", "mask") == "mask"}
        out: list[Finding] = []
        for f in findings:
            if getattr(f, "decision", "mask") != "mask":
                out.append(f)
                continue
            needs = combo.get(f.type)
            if not needs:
                out.append(f)
                continue
            if any(t in present for t in needs):
                out.append(f)
        return out

    def _context_ml_for_system(self, system: Optional[str], need_context_ml: bool) -> bool:
        """Enable ML only when a context-defined PII type is actually needed.

        Routing is separate from detection logic: a system may deliberately
        keep ML off for a compatibility/high-RPS profile.
        """
        if not need_context_ml:
            return False
        master = os.getenv("CONTEXT_ML_ENABLED", os.getenv("NER_ENABLED", "0"))
        if master != "1":
            return False
        if not system:
            return False
        if system in self.config.systems:
            flag = self.config.systems[system].use_context_ml
            if flag is not None:
                return flag
        if system in {"autotest", "high_rps", "format_only"}:
            return False
        return system == "demo"

    def _ner_for_system(self, system: Optional[str], need_person: bool) -> bool:
        """Backward-compatible alias for the pre-v2 routing API."""
        return self._context_ml_for_system(system, need_person)


    def detect(self, text: str, system: Optional[str] = None) -> list[Finding]:
        allowed_set = self._allowed_types(system)
        need_context_ml = allowed_set is None or bool(allowed_set & CONTEXT_TYPES)
        findings = detect_pii(
            text, enable_ner=self._context_ml_for_system(system, need_context_ml)
        )
        if allowed_set:
            findings = [
                f
                for f in findings
                if f.type in allowed_set or f.type == "REDACTED_SPAN"
            ]
        findings = self._apply_combo(findings, self._combo_policy(system))
        return findings

    def _aad(self, namespace: str, payload_id: str) -> str:
        return f"{namespace}:{payload_id}"

    def process(self, payload: str, payload_id: str, system: Optional[str] = None) -> str:
        if not payload_id:
            raise ProcessError(400, "payload_id must be non-empty")

        namespace = NS_AUTOTEST
        live = self.store.get_live(namespace, payload_id)
        if live:
            fp = hmac_hex(payload)
            if fp == live.original_fp:
                return decrypt(live.masked_enc, self._aad(namespace, payload_id))
            if fp == live.masked_fp:
                return decrypt(live.original_enc, self._aad(namespace, payload_id))
            raise ProcessError(409, "payload_id already bound to a different payload")

        if self.store.get_seen(namespace, payload_id):
            raise ProcessError(410, "operation expired")

        findings = self.detect(payload, system)
        masked = apply_dev_redact(payload, findings)
        aad = self._aad(namespace, payload_id)
        state = OperationState(
            payload_id=payload_id,
            namespace=namespace,
            original_fp=hmac_hex(payload),
            masked_fp=hmac_hex(masked),
            masked_enc=encrypt(masked, aad),
            original_enc=encrypt(payload, aad),
            system=system or "",
            mask_strategy="dev_redact_v1",
        )
        created = self.store.create_atomic(state)
        if not created:
            # lost race — reload winner
            live = self.store.get_live(namespace, payload_id)
            if not live:
                if self.store.get_seen(namespace, payload_id):
                    raise ProcessError(410, "operation expired")
                raise ProcessError(503, "state store race failed")
            fp = hmac_hex(payload)
            if fp == live.original_fp:
                return decrypt(live.masked_enc, aad)
            if fp == live.masked_fp:
                return decrypt(live.original_enc, aad)
            raise ProcessError(409, "payload_id already bound to a different payload")

        log.debug("mask payload_id=%s findings=%d", payload_id, len(findings))
        return masked

    def proxy_protect(
        self,
        text: str,
        *,
        consumer_id: str,
        operation_id: str,
        system: str,
    ) -> tuple[str, OperationState]:
        """Tokenize for LLM proxy; store mapping encrypted."""
        namespace = f"{NS_PROXY}:{consumer_id}"
        if self.store.get_live(namespace, operation_id):
            raise ProcessError(409, "operation_id already exists")
        if self.store.get_seen(namespace, operation_id):
            raise ProcessError(410, "operation expired")

        findings = self.detect(text, system)
        masked, mapping = apply_scoped_tokens(text, findings)
        aad = self._aad(namespace, operation_id)
        state = OperationState(
            payload_id=operation_id,
            namespace=namespace,
            original_fp=hmac_hex(text),
            masked_fp=hmac_hex(masked),
            masked_enc=encrypt(masked, aad),
            original_enc=encrypt(text, aad),
            system=system,
            mask_strategy="scoped_tokens_v1",
            tokens_enc=encrypt(json.dumps(mapping, ensure_ascii=False), aad),
        )
        if not self.store.create_atomic(state):
            raise ProcessError(409, "operation_id already exists")
        return masked, state

    def proxy_restore(
        self,
        text: str,
        *,
        consumer_id: str,
        operation_id: str,
        system: str,
    ) -> str:
        sys_cfg = self.config.systems.get(system)
        if not sys_cfg or not sys_cfg.enabled:
            raise ProcessError(403, "system not allowed")
        if not sys_cfg.allow_demask:
            raise ProcessError(403, "demask not allowed for this system")

        namespace = f"{NS_PROXY}:{consumer_id}"
        live = self.store.get_live(namespace, operation_id)
        if not live:
            if self.store.get_seen(namespace, operation_id):
                raise ProcessError(410, "operation expired")
            raise ProcessError(404, "operation not found")
        if live.system and live.system != system:
            raise ProcessError(403, "operation belongs to another system")

        aad = self._aad(namespace, operation_id)
        mapping = json.loads(decrypt(live.tokens_enc, aad)) if live.tokens_enc else {}
        return restore_scoped_tokens(text, mapping)
