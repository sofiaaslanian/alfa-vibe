"""All rule-based PII detectors (format + format-context)."""

from __future__ import annotations

import re

from app.pii.detect import Finding


def _window(text: str, start: int, end: int, size: int = 60) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def _has_any(ctx: str, patterns: list[str]) -> bool:
    return any(re.search(p, ctx, re.IGNORECASE) for p in patterns)


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


# --- email ---
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9._%+-])"
)
SERVICE_DOMAINS = {"bank.ru", "support.bank.ru", "alfabank.ru", "example.com"}
SERVICE_LOCAL = {"support", "noreply", "no-reply", "info", "help", "admin"}


def detect_email(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in EMAIL_RE.finditer(text):
        value = m.group(0)
        local, _, domain = value.partition("@")
        if domain.lower() in SERVICE_DOMAINS or local.lower() in SERVICE_LOCAL:
            continue
        out.append(Finding("EMAIL", m.start(), m.end(), 0.99, "email_rule_v1"))
    return out

# --- phone ---
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?7|8)[\s\-\(\)]*\d{3}[\s\-\(\)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)"
)
PHONE_NEG = [r"колл[\-\s]?центр", r"call[\-\s]?center", r"горяч\w*\s+лин", r"телефон\s+поддержк"]


def detect_phone(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PHONE_RE.finditer(text):
        digits = _digits_only(m.group(0))
        if digits.startswith("8") and len(digits) == 11:
            digits = "7" + digits[1:]
        if not (len(digits) == 11 and digits.startswith("7")):
            continue
        if _has_any(_window(text, m.start(), m.end()), PHONE_NEG):
            continue
        out.append(Finding("PHONE", m.start(), m.end(), 0.98, "phone_rule_v1"))
    return out

# --- inn ---
INN_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")


def _inn12_valid(inn: str) -> bool:
    if len(inn) != 12 or not inn.isdigit():
        return False
    coeffs1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coeffs2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    n = [int(c) for c in inn]
    d11 = sum(c * n[i] for i, c in enumerate(coeffs1)) % 11 % 10
    d12 = sum(c * n[i] for i, c in enumerate(coeffs2)) % 11 % 10
    return d11 == n[10] and d12 == n[11]


def detect_inn(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in INN_RE.finditer(text):
        if not _inn12_valid(m.group(1)):
            continue
        out.append(Finding("INN", m.start(), m.end(), 0.99, "inn_rule_v1"))
    return out

# --- card ---
CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]*?){13,19}(?!\d)")


def _luhn_ok(number: str) -> bool:
    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    total = 0
    for i, ch in enumerate(number[::-1]):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_card(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARD_RE.finditer(text):
        digits = _digits_only(m.group(0))
        if not _luhn_ok(digits):
            continue
        out.append(Finding("PAYMENT_CARD", m.start(), m.end(), 0.99, "card_rule_v1"))
    return out

# --- address ---
ADDRESS_RE = re.compile(
    r"(?:(?:г\.|город)\s*[А-Яа-яЁёA-Za-z\-]+(?:\s*,\s*)?)?"
    r"(?:ул\.|улица|пр\.|проспект|пер\.|переулок)\s*[А-Яа-яЁёA-Za-z0-9\-\.\s]+?"
    r"(?:\s*,\s*|\s+)(?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?"
    r"(?:(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+)?",
    re.IGNORECASE,
)
ADDRESS_NEG = [r"отделен\w*\s+банк", r"филиал", r"офис\s+банк", r"адрес\s+отделен", r"адрес\s+банк"]


def detect_address(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ADDRESS_RE.finditer(text):
        if _has_any(_window(text, m.start(), m.end(), 80), ADDRESS_NEG):
            continue
        out.append(Finding("ADDRESS", m.start(), m.end(), 0.9, "address_rule_v1"))
    return out

# --- dates ---
DATE_RE = re.compile(
    r"(?<!\d)(?:0?[1-9]|[12]\d|3[01])[./](?:0?[1-9]|1[0-2])[./](?:19|20)\d{2}(?!\d)"
)


def _detect_date(text, pii_type, detector, positive, negative):
    out = []
    for m in DATE_RE.finditer(text):
        ctx = _window(text, m.start(), m.end(), 50)
        if not _has_any(ctx, positive) or _has_any(ctx, negative):
            continue
        out.append(Finding(pii_type, m.start(), m.end(), 0.95, detector))
    return out


def detect_birth_date(text: str) -> list[Finding]:
    return _detect_date(
        text, "BIRTH_DATE", "birth_date_rule_v1",
        [r"дат[аы]\s+рожден", r"родил(?:ся|ась)", r"\bдр\b"],
        [r"заседани", r"опубликован", r"срок", r"встреч"],
    )


def detect_passport_issue_date(text: str) -> list[Finding]:
    return _detect_date(
        text, "PASSPORT_ISSUE_DATE", "passport_issue_date_rule_v1",
        [r"выдан", r"дата\s+выдач"],
        [r"опубликован", r"заседани"],
    )

# --- passport ---
PASSPORT_RE = re.compile(
    r"(?<!\d)(\d{2}\s?\d{2})(?:\s*(?:серия|номер)?\s*)?[\s\-]*(?:номер\s+)?(\d{6})(?!\d)",
    re.IGNORECASE,
)


def detect_passport(text: str) -> list[Finding]:
    out = []
    for m in PASSPORT_RE.finditer(text):
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, [r"паспорт", r"серия", r"номер\s+паспорт"]):
            continue
        if _has_any(ctx, [r"номер\s+заказ", r"заявк", r"номер\s+договор"]):
            continue
        out.append(Finding("PASSPORT", m.start(), m.end(), 0.96, "passport_rule_v1"))
    return out

# --- subdivision ---
SUB_RE = re.compile(r"(?<!\d)\d{3}-\d{3}(?!\d)")


def detect_subdivision(text: str) -> list[Finding]:
    out = []
    for m in SUB_RE.finditer(text):
        if not _has_any(_window(text, m.start(), m.end()), [r"код\s+подраздел", r"подраздел"]):
            continue
        out.append(Finding("SUBDIVISION_CODE", m.start(), m.end(), 0.97, "subdivision_code_rule_v1"))
    return out

# --- driver license ---
VU_RE = re.compile(r"(?<!\d)(\d{2}\s?\d{2})[\s\-]*(\d{6})(?!\d)")


def detect_driver_license(text: str) -> list[Finding]:
    out = []
    for m in VU_RE.finditer(text):
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, [r"водительск", r"\bву\b", r"удостоверен", r"права"]):
            continue
        if _has_any(ctx, [r"заявк", r"номер\s+заказ"]):
            continue
        out.append(Finding("DRIVER_LICENSE", m.start(), m.end(), 0.95, "driver_license_rule_v1"))
    return out

# --- cvv / pin ---
CVV_RE = re.compile(r"(?<!\d)\d{3,4}(?!\d)")
PIN_RE = re.compile(r"(?<!\d)\d{4,6}(?!\d)")


def detect_cvv(text: str) -> list[Finding]:
    out = []
    for m in CVV_RE.finditer(text):
        ctx = _window(text, m.start(), m.end(), 30)
        if not _has_any(ctx, [r"\bcvv2?\b", r"\bcvc2?\b"]):
            continue
        if _has_any(ctx, [r"код\s+офис", r"пин", r"\bpin\b"]):
            continue
        out.append(Finding("CVV", m.start(), m.end(), 0.97, "cvv_rule_v1"))
    return out


def detect_pin(text: str) -> list[Finding]:
    out = []
    for m in PIN_RE.finditer(text):
        ctx = _window(text, m.start(), m.end(), 40)
        if not _has_any(ctx, [r"\bpin\b", r"пин[\-\s]?код", r"\bпин\b"]):
            continue
        if _has_any(ctx, [r"код\s+двер", r"код\s+офис", r"\bcvv", r"\bcvc"]):
            continue
        out.append(Finding("PIN", m.start(), m.end(), 0.96, "pin_rule_v1"))
    return out

RULE_DETECTORS = [
    detect_email,
    detect_phone,
    detect_inn,
    detect_card,
    detect_address,
    detect_birth_date,
    detect_passport_issue_date,
    detect_passport,
    detect_subdivision,
    detect_driver_license,
    detect_cvv,
    detect_pin,
]


def detect_all_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for detector in RULE_DETECTORS:
        findings.extend(detector(text))
    return findings
