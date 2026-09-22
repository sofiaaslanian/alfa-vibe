"""All rule-based PII detectors (format + format-context + labelled fields)."""

from __future__ import annotations

import re

from app.pii.detect import Finding


def _window(text: str, start: int, end: int, size: int = 60) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def _has_any(ctx: str, patterns: list[str]) -> bool:
    return any(re.search(p, ctx, re.IGNORECASE) for p in patterns)


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def _trim_value_span(text: str, start: int, end: int) -> tuple[int, int] | None:
    """Trim spaces/punct from value; drop trailing sentence punct."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    while end > start and text[end - 1] in ".,;:!?»\"'":
        end -= 1
    if start >= end:
        return None
    return start, end


# --- email ---
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9._%+-])"
)
# Only real service mailboxes — not generic example.com (acceptance EMAIL_2).
SERVICE_DOMAINS = {"bank.ru", "support.bank.ru", "alfabank.ru"}
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
INN_POS = [r"\bинн\b", r"идентификационн\w*\s+номер\s+налогоплательщик"]
INN_NEG = [
    r"номер\s+договор",
    r"номер\s+заказ",
    r"идентификатор\s+операц",
    r"номер\s+заявк",
    r"артикул",
]


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
        ctx = _window(text, m.start(), m.end(), 80)
        if _has_any(ctx, INN_NEG) and not _has_any(ctx, INN_POS):
            continue
        if not _has_any(ctx, INN_POS):
            # checksum alone is not enough without INN role (acceptance hard_negatives)
            continue
        out.append(Finding("INN", m.start(), m.end(), 0.99, "inn_rule_v1"))
    return out


# --- card ---
CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]*?){13,19}(?!\d)")
CARD_POS = [r"карт", r"card", r"пан\b", r"\bpan\b"]
CARD_NEG = [
    r"идентификатор\s+операц",
    r"номер\s+заказ",
    r"номер\s+договор",
    r"номер\s+заявк",
    r"артикул",
]


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
        ctx = _window(text, m.start(), m.end(), 80)
        if _has_any(ctx, CARD_NEG):
            continue
        if not _has_any(ctx, CARD_POS):
            continue
        out.append(Finding("PAYMENT_CARD", m.start(), m.end(), 0.99, "card_rule_v1"))
    return out


# --- address ---
# City-prefix optional; capture from city or street through house/apt.
ADDRESS_RE = re.compile(
    r"(?:"
    r"(?:г\.|город)\s*[А-Яа-яЁёA-Za-z\-]+"
    r"|"
    r"[А-ЯЁ][а-яёA-Za-z\-]+"
    r")"
    r"\s*,\s*"
    r"(?:ул\.|улица|пр\.|проспект|пер\.|переулок)\s*[А-Яа-яЁёA-Za-z0-9\-\.\s]+?"
    r"(?:\s*,\s*|\s+)(?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?"
    r"(?:(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+)?"
    r"|"
    r"(?:ул\.|улица|пр\.|проспект|пер\.|переулок)\s*[А-Яа-яЁёA-Za-z0-9\-\.\s]+?"
    r"(?:\s*,\s*|\s+)(?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?"
    r"(?:(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+)?",
    re.IGNORECASE,
)
ADDRESS_NEG = [
    r"отделен\w*\s+банк",
    r"филиал",
    r"офис\s+банк",
    r"адрес\s+отделен",
    r"адрес\s+банк",
    r"адрес\s+офис",
    r"офис\s+компани",
    r"адрес\s+офиса\s+компани",
]


def detect_address(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ADDRESS_RE.finditer(text):
        if _has_any(_window(text, m.start(), m.end(), 80), ADDRESS_NEG):
            continue
        out.append(Finding("ADDRESS", m.start(), m.end(), 0.9, "address_rule_v1"))
    return out


# --- dates (numeric + textual) ---
DATE_NUM_RE = re.compile(
    r"(?<!\d)(?:0?[1-9]|[12]\d|3[01])[./](?:0?[1-9]|1[0-2])[./](?:19|20)\d{2}(?!\d)"
)
MONTHS = (
    r"января|февраля|марта|апреля|мая|июня|июля|августа|"
    r"сентября|октября|ноября|декабря"
)
DATE_TEXT_RE = re.compile(
    rf"(?<!\d)(?:0?[1-9]|[12]\d|3[01])\s+(?:{MONTHS})\s+(?:19|20)\d{{2}}(?:\s+года)?",
    re.IGNORECASE,
)

BIRTH_POS = [r"дат[аы]\s+рожден", r"родил(?:ся|ась)", r"\bдр\b"]
BIRTH_NEG = [r"заседани", r"опубликован", r"срок", r"встреч", r"публикац"]
ISSUE_POS = [r"дата\s+выдач[аи]\s+паспорт", r"паспорт\s+выдан", r"выдан[ао]?\s+паспорт"]
ISSUE_NEG = [
    r"опубликован",
    r"заседани",
    r"дата\s+выдач[аи]\s+заказ",
    r"выдач[аи]\s+заказ",
]


def _detect_date_forms(text: str, pii_type: str, detector: str, positive, negative) -> list[Finding]:
    out: list[Finding] = []
    for regex in (DATE_NUM_RE, DATE_TEXT_RE):
        for m in regex.finditer(text):
            ctx = _window(text, m.start(), m.end(), 60)
            if not _has_any(ctx, positive) or _has_any(ctx, negative):
                continue
            # "Паспорт выдан ГУ МВД" is issuer, not a date
            if pii_type == "PASSPORT_ISSUE_DATE" and re.match(
                r"(?i)\s*(?:ГУ|ОМВД|УВД|МВД|ОВД|ТП)\b", text[m.start() : m.start() + 12]
            ):
                continue
            span = _trim_value_span(text, m.start(), m.end())
            if not span:
                continue
            out.append(Finding(pii_type, span[0], span[1], 0.95, detector))
    return out


def detect_birth_date(text: str) -> list[Finding]:
    return _detect_date_forms(text, "BIRTH_DATE", "birth_date_rule_v1", BIRTH_POS, BIRTH_NEG)


def detect_passport_issue_date(text: str) -> list[Finding]:
    # Positive also: bare "Паспорт выдан <date>"
    return _detect_date_forms(
        text,
        "PASSPORT_ISSUE_DATE",
        "passport_issue_date_rule_v1",
        [r"выдан", r"дата\s+выдач"],
        ISSUE_NEG,
    )


# --- passport (split series/number when labelled separately) ---
PASSPORT_SPLIT_RE = re.compile(
    r"серия\s+(\d{2}\s?\d{2})\s*,?\s*номер\s+(\d{6})",
    re.IGNORECASE,
)
PASSPORT_COMBINED_RE = re.compile(
    r"(?<!\d)(\d{2}\s\d{2}\s\d{6}|\d{4}\s?\d{6}|\d{10})(?!\d)"
)
PASSPORT_POS = [r"паспорт"]
PASSPORT_NEG = [r"номер\s+заказ", r"заявк", r"номер\s+договор", r"артикул", r"накладн"]


def detect_passport(text: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[tuple[int, int]] = set()

    for m in PASSPORT_SPLIT_RE.finditer(text):
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, PASSPORT_POS):
            continue
        if _has_any(ctx, PASSPORT_NEG):
            continue
        for g in (1, 2):
            s, e = m.start(g), m.end(g)
            out.append(Finding("PASSPORT", s, e, 0.96, "passport_rule_v1"))
            covered.add((s, e))
        covered.add((m.start(), m.end()))

    for m in PASSPORT_COMBINED_RE.finditer(text):
        if any(not (m.end() <= a or m.start() >= b) for a, b in covered):
            continue
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, PASSPORT_POS):
            continue
        if _has_any(ctx, PASSPORT_NEG):
            continue
        # Avoid swallowing subdivision-like or VU without passport word nearby
        digits = _digits_only(m.group(1))
        if len(digits) not in (10,):
            continue
        out.append(Finding("PASSPORT", m.start(1), m.end(1), 0.96, "passport_rule_v1"))
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
VU_SPLIT_RE = re.compile(
    r"серия\s+(\d{2}\s\d{2})\s*,?\s*номер\s+(\d{6})",
    re.IGNORECASE,
)
VU_COMBINED_RE = re.compile(r"(?<!\d)(\d{10}|\d{2}\s\d{2}\s\d{6})(?!\d)")
VU_POS = [r"водительск", r"\bву\b", r"удостоверен", r"права"]
VU_NEG = [r"заявк", r"номер\s+заказ", r"накладн", r"паспорт"]


def detect_driver_license(text: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[tuple[int, int]] = set()

    for m in VU_SPLIT_RE.finditer(text):
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, VU_POS) or _has_any(ctx, VU_NEG):
            continue
        for g in (1, 2):
            s, e = m.start(g), m.end(g)
            out.append(Finding("DRIVER_LICENSE", s, e, 0.95, "driver_license_rule_v1"))
            covered.add((s, e))
        covered.add((m.start(), m.end()))

    for m in VU_COMBINED_RE.finditer(text):
        if any(not (m.end() <= a or m.start() >= b) for a, b in covered):
            continue
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, VU_POS) or _has_any(ctx, VU_NEG):
            continue
        out.append(Finding("DRIVER_LICENSE", m.start(1), m.end(1), 0.95, "driver_license_rule_v1"))
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
        if _has_any(
            ctx,
            [
                r"код\s+двер",
                r"код\s+офис",
                r"\bcvv",
                r"\bcvc",
                r"\bsim\b",
                r"сим[\-\s]?карт",
            ],
        ):
            continue
        out.append(Finding("PIN", m.start(), m.end(), 0.96, "pin_rule_v1"))
    return out


# --- labelled / role contextual fields ---
PLACE_LABEL_RE = re.compile(
    r"(?:место\s+рожден\w*|родил(?:ся|ась)\s+в)\s*[:\-]?\s*",
    re.IGNORECASE,
)
PLACE_VALUE_RE = re.compile(r"[А-ЯЁA-Z][А-Яа-яЁёA-Za-z\-]*(?:\s+[А-Яа-яЁёA-Za-z\-]+)?")
PLACE_NEG = [r"место\s+проведен", r"конференц", r"встреч[аиуе]", r"пройд[её]т"]


def detect_place_of_birth(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PLACE_LABEL_RE.finditer(text):
        ctx = _window(text, m.start(), m.end(), 40)
        if _has_any(ctx, PLACE_NEG):
            continue
        # "родился в" uses role; "Место рождения:" uses label
        if re.search(r"место\s+проведен", text[max(0, m.start() - 20) : m.end() + 40], re.I):
            continue
        rest = text[m.end() :]
        vm = PLACE_VALUE_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        # hard_neg: "Конференция пройдёт в Москве" — PLACE_LABEL_RE shouldn't match
        out.append(Finding("PLACE_OF_BIRTH", span[0], span[1], 0.93, "place_of_birth_rule_v1"))
    return out


CITIZEN_LABEL_RE = re.compile(
    r"(?:гражданство(?:\s+клиента)?\s*:\s*|гражданин(?:ка)?\s+)",
    re.IGNORECASE,
)
CITIZEN_VALUE_RE = re.compile(
    r"(?:РФ|Росси[яи]|[А-ЯЁ][а-яё]+(?:стана|ской|ии|ия)?)",
)
CITIZEN_NEG = [
    r"не\s+требуется",
    r"правил[ао]\s+получен",
    r"получен\w*\s+гражданств",
]


def detect_citizenship(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CITIZEN_LABEL_RE.finditer(text):
        ctx = _window(text, m.start(), m.end() + 30, 80)
        if _has_any(ctx, CITIZEN_NEG):
            continue
        # "гражданство РФ не требуется" — label matches "гражданство" via colon form only;
        # our label requires ":" or "гражданин "
        rest = text[m.end() :]
        vm = CITIZEN_VALUE_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        # skip if "не требуется" after value
        after = text[e : e + 40]
        if re.search(r"не\s+требуется", after, re.I):
            continue
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        out.append(Finding("CITIZENSHIP", span[0], span[1], 0.92, "citizenship_rule_v1"))
    return out


ISSUER_ORG_RE = re.compile(
    r"(?:ГУ|ОМВД|УВД|МВД|ОВД|ТП|УФМС)\s+[А-Яа-яЁёA-Za-z0-9\.\-\s]+",
)
ISSUER_LABEL_RE = re.compile(
    r"(?:кем\s+выдан\s+паспорт\s*:\s*|паспорт\s+выдан\s+)",
    re.IGNORECASE,
)
ISSUER_NEG = [r"справочник", r"новость", r"опубликован"]


def detect_passport_issuer(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ISSUER_LABEL_RE.finditer(text):
        ctx = _window(text, m.start(), m.end() + 50, 100)
        if _has_any(ctx, ISSUER_NEG):
            continue
        rest = text[m.end() :]
        # Must look like an organ, not a date
        if DATE_NUM_RE.match(rest) or DATE_TEXT_RE.match(rest):
            continue
        vm = ISSUER_ORG_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        out.append(Finding("PASSPORT_ISSUER", span[0], span[1], 0.94, "passport_issuer_rule_v1"))
    return out


CARDHOLDER_LABEL_RE = re.compile(
    r"(?:имя\s+держателя\s+карты|держатель\s+карты)\s*:\s*",
    re.IGNORECASE,
)
CARDHOLDER_VALUE_RE = re.compile(
    r"(?:[A-Z][A-Za-z]+\s+[A-Z][A-Za-z]+|[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+)"
)
CARDHOLDER_NEG = [r"докладчик", r"автор", r"поэт", r"писател"]


def detect_cardholder_name(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARDHOLDER_LABEL_RE.finditer(text):
        if _has_any(_window(text, m.start(), m.end()), CARDHOLDER_NEG):
            continue
        rest = text[m.end() :]
        vm = CARDHOLDER_VALUE_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        out.append(Finding("CARDHOLDER_NAME", span[0], span[1], 0.94, "cardholder_rule_v1"))
    return out


# Labelled FIO — complements NER for explicit fields
PERSON_LABEL_RE = re.compile(
    r"(?:ФИО(?:\s+клиента)?|ф\.?\s*и\.?\s*о\.?)\s*:\s*",
    re.IGNORECASE,
)
PERSON_VALUE_RE = re.compile(
    r"[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+){1,2}"
)
# Role: "Клиент Петрова Анна ..." — works with NER_ENABLED=0 for load path
# Name tokens must start with uppercase (no IGNORECASE on the value).
PERSON_CLIENT_RE = re.compile(
    r"(?<![А-Яа-яЁёA-Za-z])"
    r"(?i:клиент|заявитель|пользователь)\s+"
    r"([А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+){1,2})"
    r"(?=[\s,.;:!?»\"']|$)"
)


def detect_person_labelled(text: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[tuple[int, int]] = set()
    for m in PERSON_LABEL_RE.finditer(text):
        rest = text[m.end() :]
        vm = PERSON_VALUE_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        covered.add(span)
        out.append(Finding("PERSON", span[0], span[1], 0.97, "person_label_rule_v1"))
    for m in PERSON_CLIENT_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if any(not (e <= a or s >= b) for a, b in covered):
            continue
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        out.append(Finding("PERSON", span[0], span[1], 0.9, "person_role_rule_v1"))
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
    detect_place_of_birth,
    detect_citizenship,
    detect_passport_issuer,
    detect_cardholder_name,
    detect_person_labelled,
]


def detect_all_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for detector in RULE_DETECTORS:
        findings.extend(detector(text))
    return findings
