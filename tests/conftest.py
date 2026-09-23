import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.pii.detect import detect_pii

# Jury / adversarial labels ↔ internal detector types
DETECT_TO_JURY = {
    "PERSON": "PERSON_NAME",
    "PASSPORT": "PASSPORT_NUMBER",
    "DRIVER_LICENSE": "DRIVER_LICENSE_NUMBER",
    "SUBDIVISION_CODE": "PASSPORT_DIVISION_CODE",
}
JURY_TO_DETECT = {v: k for k, v in DETECT_TO_JURY.items()}


def joined_mask_vals(text: str, typ: str, *, enable_ner: bool = False) -> list[str]:
    """Reconstruct composite mentions from adjacent part-findings."""
    fs = sorted(
        [
            f
            for f in detect_pii(text, enable_ner=enable_ner)
            if f.type == typ and getattr(f, "decision", "mask") == "mask"
        ],
        key=lambda f: f.start,
    )
    if not fs:
        return []
    groups: list[list] = [[fs[0]]]
    for f in fs[1:]:
        prev = groups[-1][-1]
        gap = text[prev.end : f.start]
        if f.start - prev.end <= 24 and all(
            ch.isspace() or ch in ",.;:—–-" or ch.lower() in "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
            for ch in gap
        ):
            # allow short address labels between parts
            groups[-1].append(f)
        else:
            groups.append([f])
    return [text[g[0].start : g[-1].end] for g in groups]


def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return not (a1 <= b0 or b1 <= a0)


def span_text(text: str, finding: dict) -> str:
    return text[finding["start"] : finding["end"]]


def alnum_offsets(text: str, start: int, end: int) -> set[int]:
    return {i for i in range(start, end) if text[i].isalnum()}


def findings_cover_span(
    text: str, findings: list[dict], start: int, end: int
) -> bool:
    """True if one exact span or several parts cover all alphanumerics in [start,end)."""
    typ = findings[0]["type"] if findings else ""
    # ADDRESS: ignore label tokens in coverage (ул./д./кв.)
    label_re = None
    if typ in {"ADDRESS"}:
        import re

        label_re = re.compile(
            r"(?i)\b(?:ул|улица|пр|пр\-т|проспект|пер|переулок|ш|шоссе|б\-р|бульвар|"
            r"наб|пл|площадь|д|дом|кв|квартира|корп|корпус|стр|г|город)\b\.?"
        )
    need = alnum_offsets(text, start, end)
    if label_re:
        for m in label_re.finditer(text[start:end]):
            for i in range(start + m.start(), start + m.end()):
                need.discard(i)
    if not need:
        return False
    if any(f["start"] == start and f["end"] == end for f in findings):
        return True
    covered: set[int] = set()
    for f in findings:
        if f["start"] >= start and f["end"] <= end:
            covered |= alnum_offsets(text, f["start"], f["end"])
    return need <= covered


def _to_jury_type(t: str) -> str:
    return DETECT_TO_JURY.get(t, t)


def _want_types(enabled_types: list[str] | None) -> set[str] | None:
    if enabled_types is None:
        return None
    want: set[str] = set()
    for t in enabled_types:
        want.add(t)
        want.add(JURY_TO_DETECT.get(t, t))
        want.add(DETECT_TO_JURY.get(t, t))
    return want


@pytest.fixture
def detect():
    def _detect(text: str, enabled_types: list[str] | None = None):
        findings = detect_pii(text, enable_ner=False)
        want = _want_types(enabled_types)

        # Bonus document detectors remain supported as explicit extensions, but
        # are intentionally outside the canonical 17-type core pipeline.
        if want:
            from app.pii import rules

            bonus = {
                "SNILS": rules.detect_snils,
                "INTERNATIONAL_PASSPORT": rules.detect_international_passport,
                "OMS": rules.detect_oms,
            }
            for typ, detector in bonus.items():
                if typ in want:
                    findings.extend(detector(text))
        out = []
        for f in findings:
            if getattr(f, "decision", "mask") != "mask":
                continue  # ALLOW = noticed UI-only, not a masked FP
            if want is not None and f.type not in want and _to_jury_type(f.type) not in want:
                continue
            d = f.to_dict()
            d["type"] = _to_jury_type(f.type)
            out.append(d)
        return out

    return _detect
