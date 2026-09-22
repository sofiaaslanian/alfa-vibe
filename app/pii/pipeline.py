"""PII detection pipeline: rules → NER → eligibility → resolver."""

from __future__ import annotations

import logging
import os

from app.pii.contract import Finding
from app.pii.eligibility import filter_findings
from app.pii.ner import NerClient
from app.pii.resolver import resolve_overlaps
from app.pii.rules import detect_all_rules

log = logging.getLogger("alfa.pii")

_ner: NerClient | None = None


def get_ner() -> NerClient:
    global _ner
    if _ner is None:
        _ner = NerClient()
    return _ner


def detect_pii(
    text: str,
    *,
    enable_ner: bool | None = None,
    fail_closed_on_ner_error: bool | None = None,
) -> list[Finding]:
    """Run full detection. NER (FIO) via NER_ENABLED=1 or enable_ner=True."""
    findings = detect_all_rules(text)

    ner = get_ner()
    use_ner = ner.enabled if enable_ner is None else enable_ner
    if use_ner:
        # Soft by default for local MVP; set NER_FAIL_CLOSED=1 in prod
        fail_closed = (
            os.getenv("NER_FAIL_CLOSED", "0") == "1"
            if fail_closed_on_ner_error is None
            else fail_closed_on_ner_error
        )
        try:
            # When enable_ner forced True, temporarily enable client
            if enable_ner is True and not ner.enabled:
                ner.enabled = True
                ner.use_local = True
            findings.extend(ner.detect(text))
        except Exception:
            log.exception("NER detection failed")
            if fail_closed:
                raise

    findings = filter_findings(text, findings)
    return resolve_overlaps(findings)
