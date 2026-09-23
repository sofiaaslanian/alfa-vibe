"""PII detection: findings, rules+NER pipeline, eligibility, resolve, apply masks."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

log = logging.getLogger("alfa.pii")


@dataclass(frozen=True)
class Finding:
    type: str
    start: int
    end: int
    score: float
    detector: str
    # mask = protect; allow = seen but policy says leave open (famous / service)
    decision: str = "mask"
    reason: str = ""
    # Composite structure part: first|middle|last|series|number|city|street|house|flat|…
    part: str = ""

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "score": self.score,
            "detector": self.detector,
        }
        if self.decision != "mask":
            d["decision"] = self.decision
        if self.reason:
            d["reason"] = self.reason
        if self.part:
            d["part"] = self.part
        return d


def maskable(findings: list[Finding]) -> list[Finding]:
    """Findings that must be redacted (default decision=mask)."""
    return [f for f in findings if getattr(f, "decision", "mask") == "mask"]


PRIORITY = {
    "PASSPORT_ISSUER": 100,
    "CARDHOLDER_NAME": 95,
    "PLACE_OF_BIRTH": 90,
    "CITIZENSHIP": 85,
    "PASSPORT": 80,
    "INTERNATIONAL_PASSPORT": 79,
    "DRIVER_LICENSE": 78,
    "SUBDIVISION_CODE": 75,
    "OMS": 74,
    "SNILS": 73,
    "BIRTH_DATE": 70,
    "PASSPORT_ISSUE_DATE": 68,
    "PAYMENT_CARD": 65,
    "INN": 60,
    "EMAIL": 55,
    "PHONE": 55,
    "CVV": 50,
    "PIN": 48,
    "ADDRESS": 40,
    "PERSON": 30,
    "REDACTED_SPAN": 20,
}

FIXED_TOKENS = {
    "PERSON",
    "ADDRESS",
    "PLACE_OF_BIRTH",
    "CITIZENSHIP",
    "PASSPORT_ISSUER",
    "CARDHOLDER_NAME",
    "REDACTED_SPAN",
}
DEFAULT_MASKS = {
    "PHONE": "+7 XXX XXX-XX-XX",
    "INN": "XXXXXXXXXXXX",
    "PAYMENT_CARD": "XXXX XXXX XXXX XXXX",
    "PERSON": "[PERSON]",
    "ADDRESS": "[ADDRESS]",
    "PLACE_OF_BIRTH": "[PLACE_OF_BIRTH]",
    "CITIZENSHIP": "[CITIZENSHIP]",
    "PASSPORT_ISSUER": "[PASSPORT_ISSUER]",
    "CARDHOLDER_NAME": "[CARDHOLDER_NAME]",
    "REDACTED_SPAN": "[REDACTED]",
    "BIRTH_DATE": "XX.XX.XXXX",
    "PASSPORT_ISSUE_DATE": "XX.XX.XXXX",
    "PASSPORT": "XXXX XXXXXX",
    "INTERNATIONAL_PASSPORT": "XX XXXXXXX",
    "DRIVER_LICENSE": "XX XX XXXXXX",
    "SUBDIVISION_CODE": "XXX-XXX",
    "SNILS": "XXX-XXX-XXX XX",
    "OMS": "XXXXXXXXXXXXXXXX",
    "CVV": "XXX",
    "PIN": "XXXX",
}

def _cluster_same_type(
    findings: list[Finding],
    typ: str,
    text: str,
    *,
    max_gap: int = 3,
) -> list[list[Finding]]:
    """Group adjacent composite parts so discourse sees the full mention."""
    items = sorted([f for f in findings if f.type == typ], key=lambda f: f.start)
    if not items:
        return []
    # ADDRESS parts leave «ул.»/«д.» in the gap — allow longer labeled gaps.
    if typ == "ADDRESS":
        max_gap = 28

    def _gap_ok(gap: str) -> bool:
        if not gap:
            return True
        if all(ch.isspace() or ch in ",.;:—–-" for ch in gap):
            return True
        if typ == "ADDRESS" and all(
            ch.isspace()
            or ch in ",.;:—–-"
            or ch.lower() in "абвгдеёжзийклмнопрстуфхцчшщъыьэюя."
            for ch in gap
        ):
            return True
        return False

    clusters: list[list[Finding]] = [[items[0]]]
    for f in items[1:]:
        prev = clusters[-1][-1]
        gap = text[prev.end : f.start]
        if f.start - prev.end <= max_gap and _gap_ok(gap):
            clusters[-1].append(f)
        else:
            clusters.append([f])
    return clusters


def filter_findings(text: str, findings: list[Finding]) -> list[Finding]:
    """Eligibility: personal vs public/service/holiday for contextual types.

    Skipped candidates stay as decision=allow so the UI can underline them
    («Жириновский» найден, маскировать не нужно).

    Composite parts (FIO tokens, address components) are judged as one cluster
    so «Иванову Ивану» / «Москва, ул. …» share a single ALLOW/MASK decision.
    """
    from app.pii.discourse import (
        should_skip_address,
        should_skip_birth_date,
        should_skip_inn,
        should_skip_person,
        should_skip_phone,
        should_skip_place_of_birth,
    )

    ALLOW_REASON = {
        "PERSON": "нет личного claim — знаменитость / третье лицо",
        "ADDRESS": "служебный / публичный адрес",
        "INN": "не клиентский ИНН",
        "PHONE": "публичный / служебный номер",
        "BIRTH_DATE": "не дата рождения клиента",
        "PLACE_OF_BIRTH": "биография / не клиент",
    }

    def _allow(f: Finding) -> Finding:
        return Finding(
            f.type,
            f.start,
            f.end,
            f.score,
            f.detector,
            decision="allow",
            reason=ALLOW_REASON.get(f.type, "policy allow"),
            part=getattr(f, "part", ""),
        )

    decided: dict[int, Finding] = {}  # id(f) → finding with decision

    for typ, skip_fn in (
        ("PERSON", should_skip_person),
        ("ADDRESS", should_skip_address),
    ):
        for cluster in _cluster_same_type(findings, typ, text):
            s, e = cluster[0].start, cluster[-1].end
            if skip_fn(text, s, e):
                for f in cluster:
                    decided[id(f)] = _allow(f)
            else:
                for f in cluster:
                    decided[id(f)] = f

    out: list[Finding] = []
    for f in findings:
        if id(f) in decided:
            out.append(decided[id(f)])
            continue
        if f.type == "INN" and should_skip_inn(text, f.start, f.end):
            out.append(_allow(f))
            continue
        if f.type == "PHONE" and should_skip_phone(text, f.start, f.end):
            out.append(_allow(f))
            continue
        if f.type == "BIRTH_DATE" and should_skip_birth_date(text, f.start, f.end):
            out.append(_allow(f))
            continue
        if f.type == "PLACE_OF_BIRTH" and should_skip_place_of_birth(text, f.start, f.end):
            out.append(_allow(f))
            continue
        out.append(f)
    return out


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Priority wins on nesting; partial overlap → REDACTED_SPAN union (no PII tail).

    ALLOW findings (famous / service) are kept as-is and do not merge into mask unions.
    """
    if not findings:
        return []
    allows = [f for f in findings if getattr(f, "decision", "mask") == "allow"]
    mask_findings = [f for f in findings if getattr(f, "decision", "mask") != "allow"]
    if not mask_findings:
        return sorted(allows, key=lambda f: f.start)

    ordered = sorted(
        mask_findings,
        key=lambda f: (-PRIORITY.get(f.type, 0), -(f.end - f.start), f.start),
    )
    accepted: list[Finding] = []

    def _overlaps(a: Finding, b: Finding) -> bool:
        return not (a.end <= b.start or a.start >= b.end)

    for cand in ordered:
        hits = [k for k in accepted if _overlaps(cand, k)]
        if not hits:
            accepted.append(cand)
            continue
        # Fully contained in an accepted span → drop
        if any(k.start <= cand.start and cand.end <= k.end for k in hits):
            continue
        # Cand fully contains some accepted → replace those
        contained = [k for k in hits if cand.start <= k.start and k.end <= cand.end]
        if contained and len(contained) == len(hits):
            accepted = [k for k in accepted if k not in contained]
            accepted.append(cand)
            continue
        # Partial overlap → merge into REDACTED_SPAN covering the union
        union_start = min([cand.start] + [k.start for k in hits])
        union_end = max([cand.end] + [k.end for k in hits])
        accepted = [k for k in accepted if k not in hits]
        accepted.append(
            Finding(
                "REDACTED_SPAN",
                union_start,
                union_end,
                min(cand.score, min(k.score for k in hits)),
                "overlap_union",
            )
        )
    # Drop ALLOW spans fully covered by a mask span (already protected).
    out = list(accepted)
    for a in allows:
        if any(k.start <= a.start and a.end <= k.end for k in accepted):
            continue
        out.append(a)
    return sorted(out, key=lambda f: f.start)


def apply_masks(text: str, findings: list[Finding], token_style: bool = False) -> str:
    if not findings:
        return text
    result = text
    counters: dict[str, int] = {}
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        original = text[f.start : f.end]
        if token_style:
            counters[f.type] = counters.get(f.type, 0) + 1
            replacement = f"<{f.type}_{counters[f.type]}>"
        elif f.type in FIXED_TOKENS:
            replacement = DEFAULT_MASKS[f.type]
        else:
            template = DEFAULT_MASKS.get(f.type) or ("X" * len(original))
            if len(template) >= len(original):
                replacement = template[: len(original)]
            else:
                replacement = (template * ((len(original) // len(template)) + 1))[: len(original)]
        result = result[: f.start] + replacement + result[f.end :]
    return result


_ner = None


def get_ner():
    global _ner
    if _ner is None:
        from app.pii.ner import NerClient

        _ner = NerClient()
    return _ner


def _normalize_structured_findings(
    text: str,
    findings: list[Finding],
) -> list[Finding]:
    """Split composite PERSON/ADDRESS spans into value-only structural parts."""
    from app.pii.parts import split_address_span, split_person_span

    normalized: list[Finding] = []
    for finding in findings:
        detector = (finding.detector or "").lower()
        is_ml = (
            detector == "ml"
            or detector.startswith("ml")
            or "ner" in detector
            or "rubert" in detector
        )
        if finding.type == "ADDRESS" and (
            is_ml or not getattr(finding, "part", "")
        ):
            normalized.extend(
                split_address_span(
                    text,
                    finding.start,
                    finding.end,
                    finding.score,
                    finding.detector,
                    decision=getattr(finding, "decision", "mask"),
                    reason=getattr(finding, "reason", "") or "",
                )
            )
            continue
        if finding.type == "PERSON" and " " in text[finding.start : finding.end]:
            normalized.extend(
                split_person_span(
                    text,
                    finding.start,
                    finding.end,
                    finding.score,
                    finding.detector,
                    decision=getattr(finding, "decision", "mask"),
                    reason=getattr(finding, "reason", "") or "",
                )
            )
            continue
        normalized.append(finding)
    return normalized


def detect_pii(
    text: str,
    *,
    enable_ner: bool | None = None,
    fail_closed_on_ner_error: bool | None = None,
) -> list[Finding]:
    """Run the canonical three-flow architecture.

    1. FORMAT: format-defined rule flow.
    2. FORMAT_CONTEXT: format candidate + contextual rule flow.
    3. CONTEXT: ML-first contextual flow; labelled rule candidates remain as a
       migration fallback until the contextual role model is fully deployed.
    4. STRUCTURE: one shared atomic/composite normalization layer.
    5. ELIGIBILITY + overlap resolver + masking downstream.
    """
    from app.pii.flows import run_detection_flows
    from app.pii.structural import normalize_structures
    from app.pii.validate import sanitize_format_findings

    ner = get_ner()
    use_ner = ner.enabled if enable_ner is None else enable_ner
    context_ml_findings: list[Finding] | None = None

    if use_ner:
        fail_closed = (
            os.getenv("NER_FAIL_CLOSED", "0") == "1"
            if fail_closed_on_ner_error is None
            else fail_closed_on_ner_error
        )
        try:
            if enable_ner is True and not ner.enabled:
                ner.enabled = True
                ner.use_local = True
            raw_entities = ner.detect_raw(text)
            from app.pii.context_ml import raw_entities_to_context_findings

            context_ml_findings = raw_entities_to_context_findings(text, raw_entities)
        except Exception:
            log.exception("NER detection failed")
            if fail_closed:
                raise

    findings = run_detection_flows(
        text,
        context_ml_findings=context_ml_findings,
    )
    findings = sanitize_format_findings(text, findings)
    findings = normalize_structures(text, findings)
    return resolve_overlaps(filter_findings(text, findings))
