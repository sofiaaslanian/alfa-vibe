"""All rule-based PII detectors (format + format-context + labelled fields)."""

from __future__ import annotations

import re

from app.pii.detect import Finding


def _window(text: str, start: int, end: int, size: int = 60) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def _left(text: str, start: int, size: int = 50) -> str:
    return text[max(0, start - size) : start]


def _right(text: str, end: int, size: int = 40) -> str:
    return text[end : min(len(text), end + size)]


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


def _nearest_label(text: str, start: int, labels: dict[str, list[str]], max_dist: int = 55) -> str | None:
    """Closest label (by end position) in the left window → role key."""
    window = text[max(0, start - max_dist) : start]
    best_key: str | None = None
    best_pos = -1
    for key, pats in labels.items():
        for p in pats:
            for m in re.finditer(p, window, re.IGNORECASE):
                if m.end() >= best_pos:
                    best_pos = m.end()
                    best_key = key
    return best_key


# --- email ---
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9_%+-])"
)
SERVICE_DOMAINS = {"bank.ru", "support.bank.ru", "alfabank.ru"}
SERVICE_LOCAL = {"support", "noreply", "no-reply", "info", "help", "admin"}
EMAIL_LABELS = {
    "real": [
        r"реальная\s+почт",
        r"почта\s+клиента",
        r"email\s+клиента",
        r'"customer"',
        r"customer",
    ],
    "fake": [
        r"пример\s+почт",
        r"пример\s+email",
        r"шаблон",
        r"template",
        r'"merchant"',
        r"merchant",
    ],
}


def detect_email(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in EMAIL_RE.finditer(text):
        value = m.group(0)
        local, _, domain = value.partition("@")
        if domain.lower() in SERVICE_DOMAINS or local.lower() in SERVICE_LOCAL:
            continue
        role = _nearest_label(text, m.start(), EMAIL_LABELS, max_dist=70)
        if role == "fake":
            continue
        out.append(Finding("EMAIL", m.start(), m.end(), 0.99, "email_rule_v1"))
    return out


# --- phone ---
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?7|8)[\s\-\(\)]*\d{3}[\s\-\(\)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)"
)
PHONE_NEG = [
    r"колл[\-\s]?центр",
    r"call[\-\s]?center",
    r"горяч\w*\s+лин",
    r"телефон\s+поддержк",
    r"телефон\s+офис",
    r"номер\s+заказ",
    r"заказ[ае]?\s*№",
    r"номер\s+заявк",
    r"артикул",
    r"идентификатор\s+транзак",
]


def detect_phone(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PHONE_RE.finditer(text):
        digits = _digits_only(m.group(0))
        if digits.startswith("8") and len(digits) == 11:
            digits = "7" + digits[1:]
        if not (len(digits) == 11 and digits.startswith("7")):
            continue
        if _has_any(_left(text, m.start(), 45), PHONE_NEG):
            continue
        out.append(Finding("PHONE", m.start(), m.end(), 0.98, "phone_rule_v1"))
    return out


# --- inn ---
INN_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
INN_LABELS = {
    "inn": [r"\bинн\b", r"идентификационн\w*\s+номер\s+налогоплательщик"],
    "other": [
        r"id\s+операц",
        r"идентификатор\s+операц",
        r"номер\s+договор",
        r"номер\s+заказ",
        r"номер\s+заявк",
        r"серийн\w*\s+код",
        r"артикул",
    ],
}


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
        if _nearest_label(text, m.start(), INN_LABELS, max_dist=50) != "inn":
            continue
        out.append(Finding("INN", m.start(), m.end(), 0.99, "inn_rule_v1"))
    return out


# --- card ---
# Include NBSP / narrow NBSP as group separators
CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-\u00a0\u202f]*?){13,19}(?!\d)")
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


def _card_formatted(raw: str) -> bool:
    return bool(re.search(r"[\s\-\u00a0\u202f]", raw)) and len(_digits_only(raw)) in (15, 16, 19)


def detect_card(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARD_RE.finditer(text):
        raw = m.group(0)
        digits = _digits_only(raw)
        if not _luhn_ok(digits):
            continue
        ctx = _window(text, m.start(), m.end(), 80)
        if _has_any(ctx, CARD_NEG):
            continue
        if not _has_any(ctx, CARD_POS) and not _card_formatted(raw):
            continue
        out.append(Finding("PAYMENT_CARD", m.start(), m.end(), 0.99, "card_rule_v1"))
    return out


# --- address ---
STREET_TYPE = r"(?:ул\.|улица|пр\.|проспект|просп\.|пер\.|переулок|ш\.|шоссе)"
HOUSE_BIT = r"(?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?"
EXTRA_BIT = r"(?:(?:\s*,\s*|\s+)(?:стр\.|строен\w*|корп\.|корпус)\s*\d+[А-Яа-яA-Za-z]?)*"
APT_BIT = r"(?:(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+)?"
CITY_BIT = r"(?:(?:г\.|город)\s*)?[А-ЯЁ][А-Яа-яЁёA-Za-z\-]+"
STREET_BIT = (
    rf"(?:"
    rf"{STREET_TYPE}\s*[А-Яа-яЁёA-Za-z0-9\-\.]+"
    rf"|"
    rf"[А-ЯЁ][А-Яа-яЁёA-Za-z0-9\-\.]+\s+{STREET_TYPE}"
    rf")"
)

ADDRESS_RE = re.compile(
    rf"(?:\d{{6}}\s*,\s*)?{CITY_BIT}\s*,\s*{STREET_BIT}"
    rf"(?:\s*,\s*|\s+){HOUSE_BIT}{EXTRA_BIT}{APT_BIT}"
    rf"|"
    rf"{STREET_TYPE}\s*[А-Яа-яЁёA-Za-z0-9\-\.\s]+?"
    rf"(?:\s*,\s*|\s+){HOUSE_BIT}{EXTRA_BIT}{APT_BIT}",
    re.IGNORECASE,
)
SHORT_ADDRESS_RE = re.compile(
    rf"(?:дом|д\.)\s*\d+[А-Яа-яA-Za-z]?(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+",
    re.IGNORECASE,
)

ADDRESS_POS = [
    r"адрес\s+(?:проживани|регистрац|клиента|для\s+корреспонденц)",
    r"адрес\s+проживани",
    r"прожива",
    r"регистрац",
    r"корреспонденц",
    r"мой\s+адрес",
    r"домашн\w*\s+адрес",
    r"доставьте",
    r"по\s+адрес",
    r"живу",
    r"живу\s*:",
]
ADDRESS_NEG = [
    r"отделен\w*",
    r"филиал",
    r"офис\s+банк",
    r"адрес\s+отделен",
    r"адрес\s+банк",
    r"адрес\s+офис",
    r"офис\s+компани",
    r"адрес\s+офиса",
    r"юридическ\w*\s+адрес",
    r"\bооо\b",
    r"пункт\s+выдач",
    r"пвз\b",
    r"работаю",
    r"работ[аые]\s+по\s+адрес",
    r"встретимся",
    r"встреча\s+назнач",
    r"магазин",
    r"находится",
]


def detect_address(text: str) -> list[Finding]:
    out: list[Finding] = []
    for regex in (ADDRESS_RE, SHORT_ADDRESS_RE):
        for m in regex.finditer(text):
            left = _left(text, m.start(), 60)
            if _has_any(left, ADDRESS_NEG):
                continue
            if not _has_any(left, ADDRESS_POS):
                continue
            if _has_any(_right(text, m.end(), 45), [r"не\s+мой\s+адрес"]):
                continue
            span = _trim_value_span(text, m.start(), m.end())
            if not span:
                continue
            out.append(Finding("ADDRESS", span[0], span[1], 0.9, "address_rule_v1"))
    return out


# --- dates ---
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

DATE_ROLE_LABELS = {
    "birth": [
        r"дат[аы]\s+рожден",
        r"родил(?:ся|ась)",
        r"\bдр\b",
        r'"birth_date"\s*:',
        r"birth_date",
    ],
    "issue": [
        r"дата\s+выдач\w*\s+паспорт",
        r"паспорт\s+выдан",
        r"выдан",
    ],
    "other": [
        r"дата\s+выдач\w*\s+заказ",
        r"дат[аы]\s+договор",
        r"договор\w*\s+подписан",
        r"подписан",
        r"заявк\w*\s*№",
        r"\bот\b",
        r"опубликован",
        r"публикац",
        r"заседани",
        r"срок",
        r"встреч",
        r"действителен",
        r"пример",
        r"заполнен",
        r"анкет",
        r"дата\s+отч[её]т",
        r"отч[её]т",
    ],
}


def _detect_role_dates(text: str, want_role: str, pii_type: str, detector: str) -> list[Finding]:
    out: list[Finding] = []
    for regex in (DATE_NUM_RE, DATE_TEXT_RE):
        for m in regex.finditer(text):
            role = _nearest_label(text, m.start(), DATE_ROLE_LABELS, max_dist=60)
            if role != want_role:
                continue
            if want_role == "birth":
                left = _left(text, m.start(), 100)
                if _has_any(left, [r"пример", r"шаблон"]) and _has_any(
                    left, [r"анкет", r"заполнен", r"формат"]
                ):
                    continue
            span = _trim_value_span(text, m.start(), m.end())
            if not span:
                continue
            out.append(Finding(pii_type, span[0], span[1], 0.95, detector))
    return out


def detect_birth_date(text: str) -> list[Finding]:
    return _detect_role_dates(text, "birth", "BIRTH_DATE", "birth_date_rule_v1")


def detect_passport_issue_date(text: str) -> list[Finding]:
    return _detect_role_dates(text, "issue", "PASSPORT_ISSUE_DATE", "passport_issue_date_rule_v1")


# --- passport ---
PASSPORT_SPLIT_RE = re.compile(
    r"серия\s+(\d{2}\s?\d{2})\s*,?\s*номер\s+(\d{6})",
    re.IGNORECASE,
)
PASSPORT_COMBINED_RE = re.compile(
    r"(?<!\d)(\d{2}\s\d{2}\s\d{6}|\d{4}\s?\d{6}|\d{10})(?!\d)"
)
PASSPORT_POS = [r"паспорт"]
PASSPORT_NEG = [
    r"номер\s+заказ",
    r"заявк",
    r"номер\s+договор",
    r"артикул",
    r"накладн",
    r"пример",
    r"формат",
    r"инструкц",
    r"шаблон",
]


def detect_passport(text: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[tuple[int, int]] = set()

    for m in PASSPORT_SPLIT_RE.finditer(text):
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, PASSPORT_POS):
            continue
        if _has_any(_left(text, m.start(), 50), PASSPORT_NEG):
            continue
        # One finding covering series → number (final-round exact-count)
        s, e = m.start(1), m.end(2)
        out.append(Finding("PASSPORT", s, e, 0.96, "passport_rule_v1"))
        covered.add((s, e))
        covered.add((m.start(), m.end()))

    for m in PASSPORT_COMBINED_RE.finditer(text):
        if any(not (m.end() <= a or m.start() >= b) for a, b in covered):
            continue
        left = _left(text, m.start(), 55)
        if not _has_any(left, PASSPORT_POS) and not _has_any(_window(text, m.start(), m.end()), PASSPORT_POS):
            continue
        if _has_any(left, PASSPORT_NEG):
            continue
        digits = _digits_only(m.group(1))
        if len(digits) not in (10,):
            continue
        out.append(Finding("PASSPORT", m.start(1), m.end(1), 0.96, "passport_rule_v1"))
    return out


# --- subdivision ---
SUB_RE = re.compile(r"(?<!\d)\d{3}-\d{3}(?!\d)")
SUB_LABELS = {
    "sub": [r"код\s+подраздел", r"подраздел"],
    "other": [r"код\s+товар", r"артикул", r"заявк\w*\s*№", r"заказ", r"клиентск\w*\s+код"],
}


def detect_subdivision(text: str) -> list[Finding]:
    out = []
    for m in SUB_RE.finditer(text):
        role = _nearest_label(text, m.start(), SUB_LABELS, max_dist=45)
        if role != "sub":
            continue
        out.append(Finding("SUBDIVISION_CODE", m.start(), m.end(), 0.97, "subdivision_code_rule_v1"))
    return out


# --- driver license ---
VU_SPLIT_RE = re.compile(
    r"серия\s+(\d{2}\s\d{2})\s*,?\s*номер\s+(\d{6})",
    re.IGNORECASE,
)
VU_COMBINED_RE = re.compile(r"(?<!\d)(\d{10}|\d{2}\s\d{2}\s\d{6})(?!\d)")
VU_POS = [r"водительск", r"\bву\b", r"в\s*/\s*у", r"удостоверен", r"права"]
VU_NEG = [r"заявк", r"номер\s+заказ", r"накладн", r"паспорт", r"пример", r"формат"]


def detect_driver_license(text: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[tuple[int, int]] = set()

    for m in VU_SPLIT_RE.finditer(text):
        ctx = _window(text, m.start(), m.end())
        if not _has_any(ctx, VU_POS) or _has_any(_left(text, m.start(), 40), VU_NEG):
            continue
        s, e = m.start(1), m.end(2)
        out.append(Finding("DRIVER_LICENSE", s, e, 0.95, "driver_license_rule_v1"))
        covered.add((s, e))
        covered.add((m.start(), m.end()))

    for m in VU_COMBINED_RE.finditer(text):
        if any(not (m.end() <= a or m.start() >= b) for a, b in covered):
            continue
        left = _left(text, m.start(), 40)
        if not _has_any(left, VU_POS) and not _has_any(_window(text, m.start(), m.end()), VU_POS):
            continue
        if _has_any(left, VU_NEG):
            continue
        out.append(Finding("DRIVER_LICENSE", m.start(1), m.end(1), 0.95, "driver_license_rule_v1"))
    return out


# --- cvv / pin ---
CVV_LABELED_RE = re.compile(
    r"(?i)(?:\bcvv2?\b|\bcvc2?\b)(?:\s+карты)?\s*[:\-—–]?\s*(\d{3,4})(?!\d)"
)
CVV_JSON_RE = re.compile(r'(?i)"\s*cvv2?\s*"\s*:\s*"?(\d{3,4})"?')
PIN_LABELED_RE = re.compile(
    r"(?i)(?:pin[\-\s]?код|пин[\-\s]?код|\bpin\b|\bпин\b)"
    r"(?:\s+банковской)?(?:\s+карты)?"
    r"\s*[:\-—–]?\s*(\d{4,6})(?!\d)"
)
PIN_JSON_RE = re.compile(r'(?i)"\s*pin\s*"\s*:\s*"?(\d{4,6})"?' )


def detect_cvv(text: str) -> list[Finding]:
    out = []
    seen: set[tuple[int, int]] = set()
    for regex in (CVV_LABELED_RE, CVV_JSON_RE):
        for m in regex.finditer(text):
            span = (m.start(1), m.end(1))
            if span in seen:
                continue
            seen.add(span)
            out.append(Finding("CVV", span[0], span[1], 0.97, "cvv_rule_v1"))
    return out


def detect_pin(text: str) -> list[Finding]:
    out = []
    seen: set[tuple[int, int]] = set()
    for regex in (PIN_LABELED_RE, PIN_JSON_RE):
        for m in regex.finditer(text):
            label = text[m.start() : m.start(1)]
            if _has_any(label, [r"код\s+двер", r"код\s+офис", r"\bsim\b", r"сим[\-\s]?карт"]):
                continue
            span = (m.start(1), m.end(1))
            if span in seen:
                continue
            seen.add(span)
            out.append(Finding("PIN", span[0], span[1], 0.96, "pin_rule_v1"))
    return out


# --- place of birth ---
PLACE_LABEL_RE = re.compile(
    r"(?:место\s+рожден\w*(?:\s+клиента)?|родил(?:ся|ась)\s+в)\s*[:\-—–]?\s*",
    re.IGNORECASE,
)
PLACE_VALUE_RE = re.compile(r"[А-ЯЁA-Z][А-Яа-яЁёA-Za-z\-]*(?:\s+[А-Яа-яЁёA-Za-z\-]+)?")
PLACE_NEG = [r"место\s+проведен", r"конференц", r"пройд[её]т"]


def detect_place_of_birth(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PLACE_LABEL_RE.finditer(text):
        if _has_any(_left(text, m.start(), 40), PLACE_NEG):
            continue
        if re.search(r"место\s+проведен", _left(text, m.start(), 30), re.I):
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
        out.append(Finding("PLACE_OF_BIRTH", span[0], span[1], 0.93, "place_of_birth_rule_v1"))
    return out


# --- citizenship ---
CITIZEN_LABEL_RE = re.compile(
    r"(?:гражданство(?:\s+клиента)?\s*[:\-—–]?\s*|гражданин(?:ка)?\s+)",
    re.IGNORECASE,
)
CITIZEN_VALUE_RE = re.compile(
    r"(?:РФ|Российская\s+Федерация|Росси[яи]|[А-ЯЁ][а-яё]+(?:стана|ской|ии|ия)?)",
)
CITIZEN_NEG = [
    r"не\s+требуется",
    r"правил[ао]\s+получен",
    r"получен\w*\s+гражданств",
]


def detect_citizenship(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CITIZEN_LABEL_RE.finditer(text):
        if _has_any(_left(text, m.start(), 40), CITIZEN_NEG):
            continue
        rest = text[m.end() :]
        vm = CITIZEN_VALUE_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        if re.search(r"не\s+требуется", text[e : e + 40], re.I):
            continue
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        out.append(Finding("CITIZENSHIP", span[0], span[1], 0.92, "citizenship_rule_v1"))
    return out


# --- passport issuer ---
ISSUER_ORG_RE = re.compile(
    r"(?:ГУ|ОМВД|УВД|МВД|ОВД|ТП|УФМС)\s+[А-Яа-яЁёA-Za-z0-9\.\-]+(?:[\s]+[А-Яа-яЁёA-Za-z0-9\.\-]+)*",
)
ISSUER_LABEL_RE = re.compile(
    r"(?:кем\s+выдан\s+паспорт\s*[:\-—–]?\s*"
    r"|паспорт\s+выдан\s*[:\-—–]?\s*"
    r"|;\s*выдан\s*[:\-—–]?\s*"
    r"|выдан\s*[:\-—–]?\s*)",
    re.IGNORECASE,
)
ISSUER_NEG = [r"справочник", r"новость", r"опубликован"]


def detect_passport_issuer(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ISSUER_LABEL_RE.finditer(text):
        labeled = m.group(0)
        if re.fullmatch(r"(?i)выдан\s*[:\-—–]?\s*", labeled):
            if not _has_any(_left(text, m.start(), 140), [r"паспорт", r"выдан"]):
                # allow list item «Выдан:» under passport section
                if not _has_any(_left(text, m.start(), 200), [r"паспорт", r"анкет"]):
                    continue
        if _has_any(_left(text, m.start(), 40), ISSUER_NEG):
            continue
        pos = m.end()
        dm = DATE_NUM_RE.match(text, pos) or DATE_TEXT_RE.match(text, pos)
        if dm:
            pos = dm.end()
        while pos < len(text) and text[pos] in " \t,;—–-":
            pos += 1
        vm = ISSUER_ORG_RE.match(text, pos)
        if not vm:
            continue
        span = _trim_value_span(text, vm.start(), vm.end())
        if not span:
            continue
        out.append(Finding("PASSPORT_ISSUER", span[0], span[1], 0.94, "passport_issuer_rule_v1"))
    return out


# --- cardholder ---
CARDHOLDER_LABEL_RE = re.compile(
    r"(?:имя\s+держателя\s+карты|держатель\s+карты|"
    r"cardholder(?!\s+company)(?:\s+name)?)\s*[:\-—–]?\s*",
    re.IGNORECASE,
)
CARDHOLDER_VALUE_RE = re.compile(
    r"(?:"
    r"[A-Z][A-Za-z]+(?:\s+[A-Z])?\s+[A-Z][A-Za-z]+"
    r"|[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+"
    r")"
)
CARDHOLDER_NEG = [r"докладчик", r"автор", r"поэт", r"писател", r"company"]


def detect_cardholder_name(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARDHOLDER_LABEL_RE.finditer(text):
        if _has_any(_left(text, m.start(), 20) + m.group(0), CARDHOLDER_NEG):
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


# --- person ---
PERSON_LABEL_RE = re.compile(
    r"(?:ФИО(?:\s+клиента)?|ф\.?\s*и\.?\s*о\.?)\s*:\s*",
    re.IGNORECASE,
)
# Capitalized or lowercase after explicit FIO label; allow hyphenated surnames
PERSON_VALUE_RE = re.compile(
    r"[А-ЯЁа-яё][А-Яа-яЁё\-]*(?:\s+[А-ЯЁа-яё][А-Яа-яЁё\-]*){1,2}"
)
PERSON_CLIENT_RE = re.compile(
    r"(?<![А-Яа-яЁёA-Za-z])"
    r"(?i:клиент|заявитель|пользователь)\s*[:\-]?\s+"
    r"([А-ЯЁ][А-Яа-яЁё\-]*(?:\s+[А-ЯЁ][А-Яа-яЁё\-]*){1,2})"
    r"(?=[\s,.;:!?»\"']|$)"
)
PERSON_CALLED_RE = re.compile(
    r"(?i:клиента?\s+зовут|зовут\s+клиента)\s+"
    r"([А-ЯЁ][А-Яа-яЁё\-]*(?:\s+[А-ЯЁ][А-Яа-яЁё\-]*){1,2})"
    r"(?=[\s,.;:!?»\"']|$)"
)
PERSON_JSON_CUSTOMER_RE = re.compile(
    r'"customer"\s*:\s*\{[^{}]*?"name"\s*:\s*"([^"]+)"',
    re.IGNORECASE | re.DOTALL,
)
PERSON_NEG = [r"ооо\s*«", r"компани", r"менеджер", r"@"]


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

    for m in PERSON_JSON_CUSTOMER_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        covered.add(span)
        out.append(Finding("PERSON", span[0], span[1], 0.95, "person_json_customer_v1"))

    for regex, score, det in (
        (PERSON_CLIENT_RE, 0.9, "person_role_rule_v1"),
        (PERSON_CALLED_RE, 0.92, "person_called_rule_v1"),
    ):
        for m in regex.finditer(text):
            s, e = m.start(1), m.end(1)
            if any(not (e <= a or s >= b) for a, b in covered):
                continue
            if _has_any(_left(text, s, 30), PERSON_NEG):
                continue
            span = _trim_value_span(text, s, e)
            if not span:
                continue
            covered.add(span)
            out.append(Finding("PERSON", span[0], span[1], score, det))
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
