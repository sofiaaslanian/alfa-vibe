"""Process service: detect → mask → shared state with HMAC retries/409/410."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from app.config import Config
from app.crypto_util import decrypt, encrypt, hmac_hex
from app.masking import apply_dev_redact, apply_scoped_tokens, restore_scoped_tokens
from app.pii.detect import Finding, detect_pii
from app.state import OperationState, StateStore

log = logging.getLogger("alfa.process")

NS_AUTOTEST = "autotest"
NS_PROXY = "proxy"

# NER is expensive — only when PERSON is in the enabled type set.
PERSON_TYPES = {"PERSON", "PERSON_NAME"}
DEV_REDACT_STYLES = {"default", "dev_redact", "redact"}
SCOPED_TOKEN_STYLES = {"token", "scoped_token", "scoped_tokens"}


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
            if not needs or any(t in present for t in needs):
                out.append(f)
        return out

    def _ner_for_system(self, system: Optional[str], need_person: bool) -> bool:
        """RuBERT only when explicitly enabled for the system (demo).

        No X-System (AlfaSonar /process) → always rules-only for RPS.
        """
        if not need_person or os.getenv("NER_ENABLED", "0") != "1":
            return False
        if not system:
            return False
        if system in self.config.systems:
            flag = self.config.systems[system].use_ner
            if flag is not None:
                return flag
        if system in {"autotest", "high_rps", "format_only"}:
            return False
        return system == "demo"

    def _mask_style(self, system: Optional[str], *, default_system: str) -> str:
        """Resolve config mask_style to one of the implemented strategies."""
        system_name = system or default_system
        cfg = self.config.systems.get(system_name)
        raw = (cfg.mask_style if cfg else "dev_redact").strip().lower()
        if raw in DEV_REDACT_STYLES:
            return "dev_redact"
        if raw in SCOPED_TOKEN_STYLES:
            return "scoped_token"
        raise ProcessError(500, f"unsupported mask_style for system '{system_name}'")

    def detect(self, text: str, system: Optional[str] = None) -> list[Finding]:
        allowed_set = self._allowed_types(system)
        need_person = allowed_set is None or bool(allowed_set & PERSON_TYPES)
        findings = detect_pii(
            text, enable_ner=self._ner_for_system(system, need_person)
        )
        if allowed_set:
            findings = [
                f
                for f in findings
                if f.type in allowed_set or f.type == "REDACTED_SPAN"
            ]
        return self._apply_combo(findings, self._combo_policy(system))

    def _aad(self, namespace: str, payload_id: str) -> str:
        return f"{namespace}:{payload_id}"

    @staticmethod
    def _trace_finish(trace: dict | None, started: float, **values) -> None:
        if trace is None:
            return
        trace.update(values)
        trace["total_ms"] = round((time.perf_counter() - started) * 1000, 3)

    def process(
        self,
        payload: str,
        payload_id: str,
        system: Optional[str] = None,
        *,
        trace: dict | None = None,
    ) -> str:
        """AlfaSonar-compatible mask/demask endpoint core.

        trace is metadata-only: timings/counts/types, never raw values.
        """
        started = time.perf_counter()
        if not payload_id:
            self._trace_finish(trace, started, mode="error", types=[], findings=0)
            raise ProcessError(400, "payload_id must be non-empty")

        namespace = NS_AUTOTEST
        t0 = time.perf_counter()
        live = self.store.get_live(namespace, payload_id)
        state_ms = (time.perf_counter() - t0) * 1000
        if live:
            fp = hmac_hex(payload)
            if fp == live.original_fp:
                result = decrypt(live.masked_enc, self._aad(namespace, payload_id))
                self._trace_finish(
                    trace, started, mode="retry", types=[], findings=0,
                    detect_ms=0.0, mask_ms=0.0, state_ms=round(state_ms, 3),
                    mask_style=live.mask_strategy,
                )
                return result
            if fp == live.masked_fp:
                result = decrypt(live.original_enc, self._aad(namespace, payload_id))
                self._trace_finish(
                    trace, started, mode="demask", types=[], findings=0,
                    detect_ms=0.0, mask_ms=0.0, state_ms=round(state_ms, 3),
                    mask_style=live.mask_strategy,
                )
                return result
            self._trace_finish(
                trace, started, mode="conflict", types=[], findings=0,
                detect_ms=0.0, mask_ms=0.0, state_ms=round(state_ms, 3),
            )
            raise ProcessError(409, "payload_id already bound to a different payload")

        t0 = time.perf_counter()
        seen = self.store.get_seen(namespace, payload_id)
        state_ms += (time.perf_counter() - t0) * 1000
        if seen:
            self._trace_finish(
                trace, started, mode="expired", types=[], findings=0,
                detect_ms=0.0, mask_ms=0.0, state_ms=round(state_ms, 3),
            )
            raise ProcessError(410, "operation expired")

        t0 = time.perf_counter()
        findings = self.detect(payload, system)
        detect_ms = (time.perf_counter() - t0) * 1000
        masked_findings = [
            f for f in findings if getattr(f, "decision", "mask") == "mask"
        ]
        types = sorted({f.type for f in masked_findings})

        style = self._mask_style(system, default_system="autotest")
        t0 = time.perf_counter()
        mapping: dict[str, str] = {}
        if style == "scoped_token":
            masked, mapping = apply_scoped_tokens(payload, masked_findings)
            mask_strategy = "scoped_tokens_v1"
        else:
            masked = apply_dev_redact(payload, masked_findings)
            mask_strategy = "dev_redact_v1"
        mask_ms = (time.perf_counter() - t0) * 1000

        aad = self._aad(namespace, payload_id)
        state = OperationState(
            payload_id=payload_id,
            namespace=namespace,
            original_fp=hmac_hex(payload),
            masked_fp=hmac_hex(masked),
            masked_enc=encrypt(masked, aad),
            original_enc=encrypt(payload, aad),
            system=system or "",
            mask_strategy=mask_strategy,
            tokens_enc=(
                encrypt(json.dumps(mapping, ensure_ascii=False), aad)
                if mapping
                else ""
            ),
        )
        t0 = time.perf_counter()
        created = self.store.create_atomic(state)
        state_ms += (time.perf_counter() - t0) * 1000
        if not created:
            # Lost race — reload winner and preserve idempotency.
            live = self.store.get_live(namespace, payload_id)
            if not live:
                if self.store.get_seen(namespace, payload_id):
                    raise ProcessError(410, "operation expired")
                raise ProcessError(503, "state store race failed")
            fp = hmac_hex(payload)
            if fp == live.original_fp:
                result = decrypt(live.masked_enc, aad)
                self._trace_finish(
                    trace, started, mode="retry_race", types=types,
                    findings=len(masked_findings), detect_ms=round(detect_ms, 3),
                    mask_ms=round(mask_ms, 3), state_ms=round(state_ms, 3),
                    mask_style=live.mask_strategy,
                )
                return result
            if fp == live.masked_fp:
                result = decrypt(live.original_enc, aad)
                self._trace_finish(
                    trace, started, mode="demask_race", types=types,
                    findings=len(masked_findings), detect_ms=round(detect_ms, 3),
                    mask_ms=round(mask_ms, 3), state_ms=round(state_ms, 3),
                    mask_style=live.mask_strategy,
                )
                return result
            raise ProcessError(409, "payload_id already bound to a different payload")

        self._trace_finish(
            trace,
            started,
            mode="mask",
            types=types,
            findings=len(masked_findings),
            detect_ms=round(detect_ms, 3),
            mask_ms=round(mask_ms, 3),
            state_ms=round(state_ms, 3),
            mask_style=mask_strategy,
        )
        return masked

    def proxy_protect(
        self,
        text: str,
        *,
        consumer_id: str,
        operation_id: str,
        system: str,
    ) -> tuple[str, OperationState]:
        """Protect prompt according to the selected system mask_style."""
        namespace = f"{NS_PROXY}:{consumer_id}"
        if self.store.get_live(namespace, operation_id):
            raise ProcessError(409, "operation_id already exists")
        if self.store.get_seen(namespace, operation_id):
            raise ProcessError(410, "operation expired")

        findings = [
            f
            for f in self.detect(text, system)
            if getattr(f, "decision", "mask") == "mask"
        ]
        style = self._mask_style(system, default_system="demo")
        mapping: dict[str, str] = {}
        if style == "scoped_token":
            masked, mapping = apply_scoped_tokens(text, findings)
            mask_strategy = "scoped_tokens_v1"
        else:
            masked = apply_dev_redact(text, findings)
            mask_strategy = "dev_redact_v1"

        aad = self._aad(namespace, operation_id)
        state = OperationState(
            payload_id=operation_id,
            namespace=namespace,
            original_fp=hmac_hex(text),
            masked_fp=hmac_hex(masked),
            masked_enc=encrypt(masked, aad),
            original_enc=encrypt(text, aad),
            system=system,
            mask_strategy=mask_strategy,
            tokens_enc=(
                encrypt(json.dumps(mapping, ensure_ascii=False), aad)
                if mapping
                else ""
            ),
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
        if live.mask_strategy == "scoped_tokens_v1":
            mapping = (
                json.loads(decrypt(live.tokens_enc, aad))
                if live.tokens_enc
                else {}
            )
            return restore_scoped_tokens(text, mapping)

        # dev_redact is reversible only for an unchanged masked payload.
        if hmac_hex(text) == live.masked_fp:
            return decrypt(live.original_enc, aad)
        raise ProcessError(
            422,
            "dev_redact cannot restore a modified LLM response; use scoped_token",
        )
