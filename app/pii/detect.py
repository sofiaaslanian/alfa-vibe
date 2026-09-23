"""PII pipeline primitives: findings, policy eligibility and overlap resolution.

Detection itself is routed by app.pii.flows; structural decomposition is
centralized in app.pii.structural.
"""

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

ALLOW_REASON = {
    "PERSON": "нет личного claim — знаменитость / третье лицо",
    "ADDRESS": "служебный / публичный адрес",
    "INN": "не клиентский ИНН",
    "PHONE": "публичный / служебный номер",
    "BIRTH_DATE": "не дата рождения клиента",
    "PLACE_OF_BIRTH": "биография / не клиент",
}

_ADDRESS_GAP_CHARS = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя."
_SEPARATOR_CHARS = ",.;:—–-"


def _gap_ok_for_type(typ: str, gap: str) -> bool:
    if not gap:
        return True
    separator_only = all(ch.isspace() or ch in _SEPARATOR_CHARS for ch in gap)
    if separator_only:
        return True
    if typ != "ADDRESS":
        return False
    return all(
        ch.isspace()
        or ch in _SEPARATOR_CHARS
        or ch.lower() in _ADDRESS_GAP_CHARS
        for ch in gap
    )


def _allow_finding(finding: Finding) -> Finding:
    return Finding(
        finding.type,
        finding.start,
        finding.end,
        finding.score,
        finding.detector,
        decision="allow",
        reason=ALLOW_REASON.get(finding.type, "policy allow"),
        part=getattr(finding, "part", ""),
    )


def _mark_cluster_decisions(
    text: str,
    findings: list[Finding],
    typ: str,
    skip_fn,
    decided: dict[int, Finding],
) -> None:
    for cluster in _cluster_same_type(findings, typ, text):
        start, end = cluster[0].start, cluster[-1].end
        skip = skip_fn(text, start, end)
        for finding in cluster:
            decided[id(finding)] = _allow_finding(finding) if skip else finding


def _apply_single_skip(
    text: str,
    finding: Finding,
    skip_functions: dict[str, object],
) -> Finding:
    skip_fn = skip_functions.get(finding.type)
    if skip_fn and skip_fn(text, finding.start, finding.end):
        return _allow_finding(finding)
    return finding


def _overlaps(a: Finding, b: Finding) -> bool:
    return not (a.end <= b.start or a.start >= b.end)


def _overlap_union(candidate: Finding, hits: list[Finding]) -> Finding:
    union_start = min([candidate.start] + [hit.start for hit in hits])
    union_end = max([candidate.end] + [hit.end for hit in hits])
    union_score = min(candidate.score, min(hit.score for hit in hits))
    return Finding("REDACTED_SPAN", union_start, union_end, union_score, "overlap_union")


def _accept_candidate(accepted: list[Finding], candidate: Finding) -> list[Finding]:
    hits = [finding for finding in accepted if _overlaps(candidate, finding)]
    if not hits:
        return [*accepted, candidate]
    if any(hit.start <= candidate.start and candidate.end <= hit.end for hit in hits):
        return accepted

    contained = [
        hit
        for hit in hits
        if candidate.start <= hit.start and hit.end <= candidate.end
    ]
    if contained and len(contained) == len(hits):
        kept = [finding for finding in accepted if finding not in contained]
        return [*kept, candidate]

    kept = [finding for finding in accepted if finding not in hits]
    return [*kept, _overlap_union(candidate, hits)]


def _append_uncovered_allows(
    accepted: list[Finding],
    allows: list[Finding],
) -> list[Finding]:
    out = list(accepted)
    for finding in allows:
        covered = any(
            mask.start <= finding.start and finding.end <= mask.end
            for mask in accepted
        )
        if not covered:
            out.append(finding)
    return out


def _cluster_same_type(
    findings: list[Finding],
    typ: str,
    text: str,
    *,
    max_gap: int = 3,
) -> list[list[Finding]]:
    """Group adjacent composite parts so discourse sees the full mention."""
    items = sorted((f for f in findings if f.type == typ), key=lambda f: f.start)
    if not items:
        return []

    gap_limit = 28 if typ == "ADDRESS" else max_gap
    clusters: list[list[Finding]] = [[items[0]]]
    for finding in items[1:]:
        previous = clusters[-1][-1]
        gap = text[previous.end : finding.start]
        is_adjacent = finding.start - previous.end <= gap_limit
        if is_adjacent and _gap_ok_for_type(typ, gap):
            clusters[-1].append(finding)
        else:
            clusters.append([finding])
    return clusters


def filter_findings(text: str, findings: list[Finding]) -> list[Finding]:
    """Eligibility: personal vs public/service/holiday for contextual types."""
    from app.pii.discourse import (
        should_skip_address,
        should_skip_birth_date,
        should_skip_inn,
        should_skip_person,
        should_skip_phone,
        should_skip_place_of_birth,
    )

    decided: dict[int, Finding] = {}
    _mark_cluster_decisions(text, findings, "PERSON", should_skip_person, decided)
    _mark_cluster_decisions(text, findings, "ADDRESS", should_skip_address, decided)

    skip_functions = {
        "INN": should_skip_inn,
        "PHONE": should_skip_phone,
        "BIRTH_DATE": should_skip_birth_date,
        "PLACE_OF_BIRTH": should_skip_place_of_birth,
    }
    return [
        decided.get(id(finding), _apply_single_skip(text, finding, skip_functions))
        for finding in findings
    ]


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Priority wins on nesting; partial overlap becomes REDACTED_SPAN union."""
    if not findings:
        return []

    allows = [
        finding
        for finding in findings
        if getattr(finding, "decision", "mask") == "allow"
    ]
    mask_findings = [
        finding
        for finding in findings
        if getattr(finding, "decision", "mask") != "allow"
    ]
    if not mask_findings:
        return sorted(allows, key=lambda finding: finding.start)

    ordered = sorted(
        mask_findings,
        key=lambda finding: (
            -PRIORITY.get(finding.type, 0),
            -(finding.end - finding.start),
            finding.start,
        ),
    )
    accepted: list[Finding] = []
    for candidate in ordered:
        accepted = _accept_candidate(accepted, candidate)

    out = _append_uncovered_allows(accepted, allows)
    return sorted(out, key=lambda finding: finding.start)


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


def _ml_fail_closed(fail_closed_on_ner_error: bool | None) -> bool:
    if fail_closed_on_ner_error is not None:
        return fail_closed_on_ner_error
    return os.getenv(
        "CONTEXT_ML_FAIL_CLOSED",
        os.getenv("NER_FAIL_CLOSED", "1"),
    ) == "1"


def _legacy_or_raw_ml_findings(text: str, ner) -> list[Finding]:
    # Instance-level detect override is a legacy/test adapter that already
    # returns canonical Findings. Prefer it over raw NER.
    if "detect" in getattr(ner, "__dict__", {}):
        return ner.detect(text)
    if hasattr(ner, "detect_raw"):
        raw_entities = ner.detect_raw(text)
        from app.pii.context_ml import raw_entities_to_context_findings

        return raw_entities_to_context_findings(text, raw_entities)
    return ner.detect(text)


def _context_ml_findings(
    text: str,
    *,
    ner,
    use_ner: bool,
    enable_ner: bool | None,
    fail_closed_on_ner_error: bool | None,
) -> list[Finding] | None:
    if not use_ner:
        return None
    try:
        if enable_ner is True and not ner.enabled:
            ner.enabled = True
            ner.use_local = True
        return _legacy_or_raw_ml_findings(text, ner)
    except Exception:
        log.exception("context ML detection failed")
        if _ml_fail_closed(fail_closed_on_ner_error):
            raise
        return None


def detect_pii(
    text: str,
    *,
    enable_ner: bool | None = None,
    fail_closed_on_ner_error: bool | None = None,
) -> list[Finding]:
    """Run three detection flows, then shared structure/policy resolution."""
    from app.pii.flows import run_detection_flows
    from app.pii.structural import normalize_structures
    from app.pii.validate import sanitize_format_findings

    ner = get_ner()
    use_ner = ner.enabled if enable_ner is None else enable_ner
    context_ml_findings = _context_ml_findings(
        text,
        ner=ner,
        use_ner=use_ner,
        enable_ner=enable_ner,
        fail_closed_on_ner_error=fail_closed_on_ner_error,
    )
    findings = run_detection_flows(
        text,
        context_ml_findings=context_ml_findings,
    )
    findings = sanitize_format_findings(text, findings)
    findings = normalize_structures(text, findings)
    return resolve_overlaps(filter_findings(text, findings))
