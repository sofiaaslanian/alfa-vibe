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


def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return not (a1 <= b0 or b1 <= a0)


def span_text(text: str, finding: dict) -> str:
    return text[finding["start"] : finding["end"]]


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
        out = []
        for f in findings:
            if want is not None and f.type not in want and _to_jury_type(f.type) not in want:
                continue
            d = f.to_dict()
            d["type"] = _to_jury_type(f.type)
            out.append(d)
        return out

    return _detect
