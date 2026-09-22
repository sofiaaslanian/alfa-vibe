"""Simple reference-aligned / placeholder masker helpers for findings."""

from __future__ import annotations

from app.pii.contract import Finding

DEFAULT_MASKS = {
    "EMAIL": "X" * 8 + "@" + "x" * 5 + ".xx",
    "PHONE": "+7 XXX XXX-XX-XX",
    "INN": "XXXXXXXXXXXX",
    "PAYMENT_CARD": "XXXX XXXX XXXX XXXX",
    "PERSON": "[PERSON]",
    "ADDRESS": "[ADDRESS]",
    "BIRTH_DATE": "XX.XX.XXXX",
    "PASSPORT_ISSUE_DATE": "XX.XX.XXXX",
    "PASSPORT": "XXXX XXXXXX",
    "DRIVER_LICENSE": "XX XX XXXXXX",
    "SUBDIVISION_CODE": "XXX-XXX",
    "CVV": "XXX",
    "PIN": "XXXX",
}


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
        else:
            template = DEFAULT_MASKS.get(f.type, "X" * len(original))
            if len(template) == len(original):
                replacement = template
            elif len(template) > len(original):
                replacement = template[: len(original)]
            else:
                replacement = (template * ((len(original) // max(len(template), 1)) + 1))[
                    : len(original)
                ]
        result = result[: f.start] + replacement + result[f.end :]
    return result
