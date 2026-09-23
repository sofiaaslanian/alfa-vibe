"""All rule-based PII detectors (format + format-context + labelled fields)."""

from __future__ import annotations

import re

from app.pii import checksums
from app.pii.claims import PERSON_SELF_CUE_FOR_RULES, PERSON_SELF_CUE_FRONT_FOR_RULES
from app.pii.detect import Finding


def _window(text: str, start: int, end: int, size: int = 60) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def _left(text: str, start: int, size: int = 50) -> str:
    return text[max(0, start - size) : start]


def _right(text: str, end: int, size: int = 40) -> str:
    return text[end : min(len(text), end + size)]


def _has_any(ctx: str, patterns: list[str]) -> bool:
    return any(re.search(p, ctx, re.IGNORECASE) for p in patterns)


def _last_match_end(ctx: str, patterns: list[str]) -> int:
    """End offset of the rightmost matching pattern in ctx, or -1."""
    best = -1
    for p in patterns:
        for m in re.finditer(p, ctx, re.IGNORECASE):
            if m.end() > best:
                best = m.end()
    return best


def _neg_wins(left: str, neg: list[str], pos: list[str]) -> bool:
    """True when a negative role is closer to the candidate than any positive."""
    n = _last_match_end(left, neg)
    if n < 0:
        return False
    p = _last_match_end(left, pos)
    return p < 0 or n >= p


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


# =============================================================================
# FORMAT-ONLY TYPES (DETECTION.md «Форматный»)
# EMAIL · PHONE · INN · PAYMENT_CARD
#
# Decision contract:
#   1) Find candidate by FORMAT (syntax / checksum / Luhn).
#   2) Protect by DEFAULT.
#   3) Drop ONLY on explicit negative role / service allowlist / invalid format.
#   4) Positive labels ("ИНН", "карта") are NOT required — they only boost score.
# Role window: ≤120 code points left of candidate (signed field may wrap after :).
# =============================================================================

ROLE_WINDOW = 120

# --- email ---
# Local@domain.tld — ASCII practical subset used in RU banking chats.
# Rejects: double @, spaces, missing TLD. Allows +tags and dots.
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-А-Яа-яЁё])"
    r"("
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}"
    r")"
    # Trailing sentence '.' must NOT block the match (not in lookahead set).
    r"(?![A-Za-z0-9_%+-])"
)
# Service / non-personal contacts — drop even if syntactically valid.
SERVICE_EMAIL_DOMAINS = {
    "bank.ru",
    "support.bank.ru",
    "example.invalid",
    # Do NOT blacklist whole alfabank.ru — employee/client mailboxes are personal.
}
SERVICE_EMAIL_LOCALS = {
    "support",
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "info",
    "help",
    "admin",
    "abuse",
    "postmaster",
    "mailer-daemon",
    "robot",
    "bot",
    "notifications",
    "notify",
    "newsletter",
}
# Positive belonging cues override domain/local service allowlist
# («Email клиента: support@bank.ru» → keep; bare support@ → drop).
EMAIL_PERSONAL_CUES = [
    r"email\s+клиент",
    r"e-?mail\s+клиент",
    r"почт[аыуе]?\s+клиент",
    r"мейл\s+клиент",
    r"mail\s+клиент",
    r"клиент\w*\s*[:\-]?\s*$",
    r"мо[яей]\s+(?:почт|email|e-?mail|мейл)",
    r"его\s+(?:почт|email|e-?mail)",
    r"е[её]\s+(?:почт|email|e-?mail)",
    r"личн\w*\s+(?:почт|email|e-?mail)",
    r"контакт\w*\s+клиент",
]
EMAIL_NEG_ROLES = [
    r"почт[аыуе]?\s+поддержк",
    r"email\s+поддержк",
    r"служб\w*\s+поддержк",
    r"техническ\w*\s+поддержк",
    r"пример\s+(?:почт|email|e-?mail)",
    r"шаблон\w*\s+(?:почт|email)",
    r"template\s+email",
    r"тестов\w*\s+(?:почт|email|адрес)",
    r'"\s*merchant\s*"',
    r"\bmerchant\b",
]


def detect_email(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in EMAIL_RE.finditer(text):
        value = m.group(1)
        # Hard reject malformed leftovers (defense in depth).
        if ".." in value or value.startswith(".") or "@." in value:
            continue
        local, _, domain = value.partition("@")
        local_l = local.lower()
        domain_l = domain.lower()
        left = _left(text, m.start(), ROLE_WINDOW)
        personal = _has_any(left, EMAIL_PERSONAL_CUES)
        # Nearest-role: later «почта клиента» beats earlier «пример почты».
        if _neg_wins(left, EMAIL_NEG_ROLES, EMAIL_PERSONAL_CUES):
            continue
        if (
            domain_l in SERVICE_EMAIL_DOMAINS or local_l in SERVICE_EMAIL_LOCALS
        ) and not personal:
            continue
        # Service domain with personal cue from a FARTHER span — still require
        # the personal cue to be nearer than a support/merchant cue.
        if (
            domain_l in SERVICE_EMAIL_DOMAINS or local_l in SERVICE_EMAIL_LOCALS
        ) and _neg_wins(left, EMAIL_NEG_ROLES + [r"поддержк", r"merchant"], EMAIL_PERSONAL_CUES):
            continue
        score = 0.99
        if personal or _has_any(left, [r"\bemail\b", r"e-?mail", r"почт", r"мейл", r"mail"]):
            score = 0.995
        out.append(Finding("EMAIL", m.start(), m.end(), score, "email_rule_v2"))
    return out

# --- phone ---
# RU default: +7 / 8 / 7 + 10 digits. Separators: space, dash, dot, (), NBSP.
# International: +CC… with 10–15 digits total (E.164), but only when explicit '+'.
PHONE_RU_RE = re.compile(
    r"(?<!\d)"
    r"(?:"
    r"\+7|8|7"
    r")"
    r"(?:[\s\-\.\u00a0\u202f]*\(?[\s\-\.\u00a0\u202f]*\d{3}[\s\-\.\u00a0\u202f]*\)?"
    r"[\s\-\.\u00a0\u202f]*\d{3}[\s\-\.\u00a0\u202f]*\d{2}[\s\-\.\u00a0\u202f]*\d{2})"
    r"(?!\d)"
)
PHONE_INTL_RE = re.compile(
    r"(?<!\d)"
    r"\+[1-9]\d{0,2}"
    r"(?:[\s\-\.\u00a0\u202f]*\(?\d{1,4}\)?)+"
    r"(?!\d)"
)
PHONE_NEG_ROLES = [
    r"колл[\-\s]?центр",
    r"call[\-\s]?center",
    r"горяч\w*\s+лин",
    r"телефон\s+поддержк",
    r"служб\w*\s+поддержк",
    r"поддержк\w*\s+альфа",
    r"альфа[\-\s]?банк\w*\s+(?:поддерж|телефон|лин)",
    r"телефон\s+офис",
    r"телефон\s+отделен",
    r"телефон\s+банка",
    r"контакт[- ]?центр",
    r"номер\s+заказ",
    r"заказ[ае]?\s*№",
    r"заказ[аеу]?\s+\d",
    r"заказ[аеу]?\s*$",
    r"номер\s+заявк",
    r"артикул",
    r"идентификатор\s+транзак",
    r"tracking",
    r"трек[\-\s]?номер",
]


def _normalize_ru_phone_digits(raw: str) -> str | None:
    digits = _digits_only(raw)
    if digits.startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]
    if digits.startswith("7") and len(digits) == 11:
        return digits
    return None


PHONE_POS_HINTS = [
    r"телефон\s+клиент",
    r"тел\.?\s+клиент",
    r"мой\s+телефон",
    r"мой\s+номер",
    r"мобильн",
    r"личн\w*\s+телефон",
    r"перезвон",
    r"позвоните\s+мне",
    r"клиент\w*",
]


def detect_phone(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, int]] = set()

    def _accept(start: int, end: int, score: float, detector: str) -> None:
        span = (start, end)
        if span in seen:
            return
        left = _left(text, start, ROLE_WINDOW)
        if _neg_wins(left, PHONE_NEG_ROLES, PHONE_POS_HINTS):
            return
        from app.pii.public_contacts import is_public_service_phone

        if is_public_service_phone(text[start:end]):
            return
        seen.add(span)
        out.append(Finding("PHONE", start, end, score, detector))

    for m in PHONE_RU_RE.finditer(text):
        if _normalize_ru_phone_digits(m.group(0)) is None:
            continue
        _accept(m.start(), m.end(), 0.98, "phone_ru_rule_v2")

    for m in PHONE_INTL_RE.finditer(text):
        raw = m.group(0)
        # Skip RU already handled (+7…).
        if raw.lstrip().startswith("+7"):
            continue
        digits = _digits_only(raw)
        # E.164: country code + subscriber = 8..15 digits total.
        if not 8 <= len(digits) <= 15:
            continue
        _accept(m.start(), m.end(), 0.9, "phone_intl_rule_v2")

    return out


# --- inn / payment card (format-first) ---
# See app/pii/ids/: checksum/Luhn → mask; decoy labels do not drop.
from app.pii.ids.inn import detect_inn  # noqa: F401
from app.pii.ids.card import detect_card  # noqa: F401


# --- address ---
# Formal + spoken:
#   «ул. Тверская, д. 10, кв. 15»
#   «Волгоградский проспект, 23»
#   «на Волгоградском проспекте, 23»
# NOTE: do NOT use IGNORECASE on named streets — it eats «живу»/«на» as name tokens.
STREET_TYPE = (
    r"(?:ул\.|улица|улице|улицу|Ул\.|Улица|"
    r"пр\.|пр\-т|проспект|проспекте|проспекту|просп\.|Проспект|"
    r"пер\.|переулок|переулке|"
    r"ш\.|шоссе|"
    r"б\-р|бульвар|бульваре|"
    r"наб\.|набережная|набережной|"
    r"пл\.|площадь|площади)"
)
HOUSE_BIT = r"(?:д\.|дом)\s*\d+[А-Яа-яA-Za-z]?"
HOUSE_BARE = r"(?:(?:д\.|дом)\s*)?\d+[А-Яа-яA-Za-z]?"
EXTRA_BIT = r"(?:(?:\s*,\s*|\s+)(?:стр\.|строен\w*|корп\.|корпус)\s*\d+[А-Яа-яA-Za-z]?)*"
APT_BIT = r"(?:(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+)?"
CITY_BIT = r"(?:(?:г\.|город)\s*)?[А-ЯЁ][А-Яа-яЁёA-Za-z\-]+"
STREET_BIT = (
    rf"(?:"
    rf"{STREET_TYPE}\s+[А-ЯЁа-яёA-Za-z0-9\-\.]+"
    rf"|"
    rf"[А-ЯЁ][А-Яа-яЁёA-Za-z0-9\-\.]+\s+{STREET_TYPE}"
    rf")"
)
# «Волгоградский проспект» / «Волгоградском проспекте» — must start with CAPITAL
NAMED_STREET = (
    rf"(?<![А-Яа-яЁёA-Za-z])"
    rf"[А-ЯЁ][а-яё\-]+(?:[аяоеуюыий]|ом|ем|ой|ей|ую)?"
    rf"(?:\s+[А-Яа-яЁё\-]+){{0,2}}"
    rf"\s+{STREET_TYPE}"
)

ADDRESS_RE = re.compile(
    rf"(?:\d{{6}}\s*,\s*)?{CITY_BIT}\s*,\s*{STREET_BIT}"
    rf"(?:\s*,\s*|\s+){HOUSE_BIT}{EXTRA_BIT}{APT_BIT}"
    rf"|"
    rf"{STREET_TYPE}\s+[А-ЯЁа-яёA-Za-z0-9\-\.\s]+?"
    rf"(?:\s*,\s*|\s+){HOUSE_BIT}{EXTRA_BIT}{APT_BIT}"
)
SHORT_ADDRESS_RE = re.compile(
    rf"(?:дом|д\.)\s*\d+[А-Яа-яA-Za-z]?(?:\s*,\s*|\s+)(?:кв\.|квартира)\s*\d+"
)
SPOKEN_ADDRESS_RE = re.compile(
    rf"(?:на\s+)?"
    rf"(?:{NAMED_STREET}|{STREET_BIT})"
    rf"(?:\s*,\s*|\s+){HOUSE_BARE}"
    rf"{EXTRA_BIT}{APT_BIT}"
)

ADDRESS_POS = [
    r"живу",
    r"жив[её]м",
    r"прожива",
    r"прописан",
    r"зарегистрирован",
    r"мой\s+адрес",
    r"наш\s+адрес",
    r"домашн\w*\s+адрес",
    r"адрес\s+проживани",
    r"адрес\s+регистрац",
    r"адрес\s+клиента",
    r"адрес\s+для\s+корреспонденц",
    r"адрес\s+доставк",
    r"адрес\s*:",
    r"доставьте",
    r"по\s+адрес[уа]",
    r"корреспонденц",
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
    r"штаб[\-\s]?квартир",
    r"склад",
]


def detect_address(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    for regex in (ADDRESS_RE, SHORT_ADDRESS_RE, SPOKEN_ADDRESS_RE):
        for m in regex.finditer(text):
            left = _left(text, m.start(), ROLE_WINDOW)
            if _has_any(left, ADDRESS_NEG):
                continue
            # Full city+street+house grammar is format-context enough;
            # short/spoken forms still need a personal/address cue.
            structured = regex is ADDRESS_RE
            if (
                not structured
                and not _has_any(left, ADDRESS_POS)
                and not re.search(r"(?i)адрес", _window(text, m.start(), m.end(), 40))
            ):
                continue
            if _has_any(_right(text, m.end(), 45), [r"не\s+мой\s+адрес"]):
                continue
            span = _trim_value_span(text, m.start(), m.end())
            if not span:
                continue
            s, e = span
            # Drop leading preposition «на » from spoken forms
            if text[s:e].lower().startswith("на "):
                s += 3
                span = _trim_value_span(text, s, e)
                if not span:
                    continue
            if span in seen:
                continue
            # Prefer longer span if nested
            if any(a <= span[0] and span[1] <= b and (a, b) != span for a, b in seen):
                continue
            seen = {s for s in seen if not (span[0] <= s[0] and s[1] <= span[1])}
            seen.add(span)
            from app.pii.parts import split_address_span

            out.extend(split_address_span(text, span[0], span[1], 0.9, "address_rule_v3"))
    # Drop nested leftovers
    out = [
        f
        for f in out
        if not any(
            o is not f and o.start <= f.start and f.end <= o.end for o in out
        )
    ]
    return out


# --- dates ---
# Order variants required by brief: DD.MM.YYYY, DD/MM/YYYY, DD-MM-YYYY,
# YYYY.MM.DD / YYYY-MM-DD / YYYY/MM/DD (and mixed separators).
_DATE_DD = r"(?:0?[1-9]|[12]\d|3[01])"
_DATE_MM = r"(?:0?[1-9]|1[0-2])"
_DATE_YYYY = r"(?:19|20)\d{2}"
_DATE_SEP = r"[./\-]"
DATE_NUM_RE = re.compile(
    rf"(?<!\d)(?:"
    rf"{_DATE_DD}{_DATE_SEP}{_DATE_MM}{_DATE_SEP}{_DATE_YYYY}"
    rf"|"
    rf"{_DATE_YYYY}{_DATE_SEP}{_DATE_MM}{_DATE_SEP}{_DATE_DD}"
    rf")(?!\d)"
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
        r"день\s+рожден",
        r"родил(?:ся|ась)",
        r"\bдр\b",
        r'"birth_date"\s*:',
        r"birth_date",
        r"дата\s+рожд",
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
        # Holidays / events — not personal birth dates
        r"новый\s+год",
        r"новогодн",
        r"рождеств",
        r"8\s*марта",
        r"23\s*феврал",
        r"9\s*мая",
        r"1\s*мая",
        r"день\s+побед",
        r"день\s+труд",
        r"день\s+народн\w*\s+единств",
        r"праздник",
        r"выходн",
        r"каникул",
        r"корпоратив",
        r"дедлайн",
    ],
}


def _detect_role_dates(text: str, want_role: str, pii_type: str, detector: str) -> list[Finding]:
    out: list[Finding] = []
    for regex in (DATE_NUM_RE, DATE_TEXT_RE):
        for m in regex.finditer(text):
            role = _nearest_label(text, m.start(), DATE_ROLE_LABELS, max_dist=60)
            if role != want_role:
                continue
            if want_role == "issue":
                # A bare «выдан» is not enough: it may describe a loan/order/document.
                # Confirm that the same sentence fragment is passport-related.
                left = _left(text, m.start(), 120)
                clause = re.split(r"[.!?\n]", left)[-1]
                if not (
                    re.search(r"(?i)дата\s+выдач\w*\s+паспорт", clause)
                    or (
                        re.search(r"(?i)паспорт\w*", clause)
                        and re.search(r"(?i)выдан\w*", clause)
                    )
                ):
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
# Cloud.ru idea: keyword + up to 3 filler words before digits; mask digit span only.
PASSPORT_SPLIT_RE = re.compile(
    r"серия\s+(\d{2}\s?\d{2})\s*,?\s*номер\s+(\d{6})",
    re.IGNORECASE,
)
PASSPORT_ANCHORED_RE = re.compile(
    r"(?i)(?:паспорт[а-яё]*|пасп\.?|серия)"
    r"(?:[\s,.:;!?()«»\"'\-]+[а-яё]+){0,3}"
    r"[\s,.:;!?()«»\"'№\-]*"
    r"(\d{2}[\s\-]?\d{2})"
    r"[\s\-]*(?:(?:№|номер)[\s№:.\-]*)?"
    r"(\d{6})"
    r"(?:\D|$)"
)
PASSPORT_COMBINED_RE = re.compile(
    r"(?<!\d)(\d{2}\s\d{2}\s\d{6}|\d{4}\s?\d{6}|\d{10})(?!\d)"
)
PASSPORT_POS = [r"паспорт", r"пасп\."]
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
        # Two digit spans — do NOT include «номер» (org: service words = excess).
        s1, e1 = m.start(1), m.end(1)
        s2, e2 = m.start(2), m.end(2)
        out.append(Finding("PASSPORT", s1, e1, 0.96, "passport_rule_v1", part="series"))
        out.append(Finding("PASSPORT", s2, e2, 0.96, "passport_rule_v1", part="number"))
        covered.add((s1, e1))
        covered.add((s2, e2))
        covered.add((m.start(), m.end()))

    for m in PASSPORT_ANCHORED_RE.finditer(text):
        s1, e1 = m.start(1), m.end(1)
        s2, e2 = m.start(2), m.end(2)
        if any(not (e1 <= a or s1 >= b) for a, b in covered):
            continue
        if any(not (e2 <= a or s2 >= b) for a, b in covered):
            continue
        left = _left(text, m.start(), 55)
        if _has_any(left, PASSPORT_NEG):
            continue
        digits = _digits_only(m.group(1) + m.group(2))
        if len(digits) != 10:
            continue
        covered.add((s1, e1))
        covered.add((s2, e2))
        out.append(Finding("PASSPORT", s1, e1, 0.96, "passport_anchored_v1", part="series"))
        out.append(Finding("PASSPORT", s2, e2, 0.96, "passport_anchored_v1", part="number"))

    for m in PASSPORT_COMBINED_RE.finditer(text):
        if any(not (m.end() <= a or m.start() >= b) for a, b in covered):
            continue
        left = _left(text, m.start(), 55)
        if not _has_any(left, PASSPORT_POS) and not _has_any(
            _window(text, m.start(), m.end()), PASSPORT_POS
        ):
            continue
        if _has_any(left, PASSPORT_NEG):
            continue
        digits = _digits_only(m.group(1))
        if len(digits) != 10:
            continue
        raw = m.group(1)
        # «45 11 123456» / «4510 123456» → series + number when separable
        sm = re.match(r"^(\d{2}\s?\d{2})\s+(\d{6})$", raw.strip())
        if sm:
            base = m.start(1)
            out.append(
                Finding(
                    "PASSPORT",
                    base + sm.start(1),
                    base + sm.end(1),
                    0.96,
                    "passport_rule_v1",
                    part="series",
                )
            )
            out.append(
                Finding(
                    "PASSPORT",
                    base + sm.start(2),
                    base + sm.end(2),
                    0.96,
                    "passport_rule_v1",
                    part="number",
                )
            )
        else:
            out.append(
                Finding("PASSPORT", m.start(1), m.end(1), 0.96, "passport_rule_v1", part="number")
            )
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
        s1, e1 = m.start(1), m.end(1)
        s2, e2 = m.start(2), m.end(2)
        out.append(Finding("DRIVER_LICENSE", s1, e1, 0.95, "driver_license_rule_v1", part="series"))
        out.append(Finding("DRIVER_LICENSE", s2, e2, 0.95, "driver_license_rule_v1", part="number"))
        covered.add((s1, e1))
        covered.add((s2, e2))
        covered.add((m.start(), m.end()))

    for m in VU_COMBINED_RE.finditer(text):
        if any(not (m.end() <= a or m.start() >= b) for a, b in covered):
            continue
        left = _left(text, m.start(), 40)
        if not _has_any(left, VU_POS) and not _has_any(_window(text, m.start(), m.end()), VU_POS):
            continue
        if _has_any(left, VU_NEG):
            continue
        out.append(
            Finding("DRIVER_LICENSE", m.start(1), m.end(1), 0.95, "driver_license_rule_v1", part="number")
        )
    return out


# --- cvv / pin ---
# Cloud.ru CVC branches: explicit cvv/cvc OR «на обороте карты» / «сзади карты».
CVV_LABELED_RE = re.compile(
    r"(?i)(?:\bcvv2?\b|\bcvc2?\b|\bцвс\b|код\s+безопасности)"
    r"(?:\s+карты)?"
    r"(?:\s*код(?:а|у|ом|е)?)?"
    r"(?:[\s,.:;!?()«»\"'\-]+[а-яё]+){0,3}"
    r"\s*[:\-—–]?\s*(\d{3,4})(?!\d)"
)
CVV_PHRASE_RE = re.compile(
    r"(?i)(?:"
    r"обороте?\s+карт[а-яё]*|"
    r"сзади\s+карт[а-яё]*|"
    r"на\s+обороте|"
    r"код\s+подтвержден[а-яё]+\s+карт[а-яё]*|"
    r"цифры\s+(?:на\s+)?обороте"
    r")(?:[^\d]{0,20})(\d{3})(?!\d)"
)
CVV_JSON_RE = re.compile(r'(?i)"\s*cv[vc]2?\s*"\s*:\s*"?(\d{3,4})"?' )
PIN_LABELED_RE = re.compile(
    r"(?i)(?:pin[\-\s]?код|пин[\-\s]?код|\bpin\b|\bпин\b)"
    r"(?:\s+банковской)?(?:\s+карты)?"
    r"\s*[:\-—–]?\s*(\d{4,6})(?!\d)"
)
PIN_JSON_RE = re.compile(r'(?i)"\s*pin\s*"\s*:\s*"?(\d{4,6})"?' )


def detect_cvv(text: str) -> list[Finding]:
    out = []
    seen: set[tuple[int, int]] = set()
    for regex in (CVV_LABELED_RE, CVV_PHRASE_RE, CVV_JSON_RE):
        for m in regex.finditer(text):
            span = (m.start(1), m.end(1))
            if span in seen:
                continue
            seen.add(span)
            out.append(Finding("CVV", span[0], span[1], 0.97, "cvv_rule_v2"))
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


# --- SNILS (bonus УЛ) ---
SNILS_RE = re.compile(r"(?<!\d)(\d{3}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{2})(?!\d)")
SNILS_POS = [r"снилс", r"страховой\s+номер", r"пенсион"]


def detect_snils(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in SNILS_RE.finditer(text):
        if not checksums.snils(m.group(1)):
            continue
        left = _left(text, m.start(), ROLE_WINDOW)
        ctx = _window(text, m.start(), m.end(), 40)
        if not _has_any(left, SNILS_POS) and not _has_any(ctx, SNILS_POS):
            continue
        out.append(Finding("SNILS", m.start(1), m.end(1), 0.97, "snils_rule_v1"))
    return out


# --- international passport (загран) ---
ZAGRAN_RE = re.compile(
    r"(?i)(?:загранпаспорт|заграничн\w*\s+паспорт|загран)"
    r"(?:[\s,.:;!?()«»\"'\-]+[а-яё]+){0,3}"
    r"[\s,.:;!?()«»\"'№\-]*"
    r"(\d{2}[\s\-]?\d{7})(?!\d)"
)


def detect_international_passport(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ZAGRAN_RE.finditer(text):
        out.append(
            Finding(
                "INTERNATIONAL_PASSPORT",
                m.start(1),
                m.end(1),
                0.94,
                "zagran_rule_v1",
            )
        )
    return out


# --- OMS medical policy ---
OMS_RE = re.compile(
    r"(?i)(?:полис\s+омс|омс|медицинск\w*\s+полис)"
    r"(?:[\s,.:;!?()«»\"'\-]+[а-яё]+){0,3}"
    r"[\s,.:;!?()«»\"'№\-]*"
    r"(\d{16})(?!\d)"
)


def detect_oms(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in OMS_RE.finditer(text):
        out.append(Finding("OMS", m.start(1), m.end(1), 0.93, "oms_rule_v1"))
    return out


# =============================================================================
# CONTEXT TYPES — role-first (DETECTION.md «Контекстный» + ADDRESS)
# Value alone is NEVER enough. Require POS role; NEG/cultural wins.
# =============================================================================

_RU_NAME = r"[А-ЯЁ][А-Яа-яЁё\-]{1,}"
_RU_NAME_LOOSE = r"[А-ЯЁа-яё][А-Яа-яЁё\-]{1,}"  # min 2 chars; allows «соня асланян»
_RU_FIO_2_3 = rf"{_RU_NAME}(?:\s+{_RU_NAME}){{1,2}}"
_RU_FIO_1_3 = rf"{_RU_NAME}(?:\s+{_RU_NAME}){{0,2}}"
_RU_FIO_LOOSE = rf"{_RU_NAME_LOOSE}(?:\s+{_RU_NAME_LOOSE}){{1,2}}"
# Self-ID only: 1–3 tokens, any case («я соня», «я Соня Асланян»)
_RU_FIO_1_3_LOOSE = rf"{_RU_NAME_LOOSE}(?:\s+{_RU_NAME_LOOSE}){{0,2}}"
_LAT_NAME = r"[A-Z][A-Za-z\-]*\.?"  # IVAN / I. / I
_LAT_FIO = rf"{_LAT_NAME}(?:[ \t]+{_LAT_NAME}){{1,2}}"
_PLACE_ATOM = (
    r"(?:г\.?\s*)?"
    r"[А-ЯЁA-Z][А-Яа-яЁёA-Za-z\-]+"
    r"(?:\s+[А-Яа-яЁёA-Za-z\-]+){0,3}"
)


# --- place of birth ---
PLACE_LABEL_RE = re.compile(
    r"(?:"
    r"место\s+рожден\w*(?:\s+клиента)?"
    r"|родил(?:ся|ась)"
    r"|рожден[ао]?"
    r"|place\s+of\s+birth"
    r"|birth\s*place"
    r")"
    r"(?:\s+в)?"
    r"\s*[:\-—–]?\s*",
    re.IGNORECASE,
)
PLACE_VALUE_RE = re.compile(_PLACE_ATOM)
PLACE_NEG = [
    r"место\s+проведен",
    r"место\s+встреч",
    r"место\s+событ",
    r"конференц",
    r"пройд[её]т",
    r"пройдет",
    r"состоится",
    r"форум",
    r"мероприят",
]


def detect_place_of_birth(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in PLACE_LABEL_RE.finditer(text):
        left = _left(text, m.start(), ROLE_WINDOW)
        label = m.group(0)
        if _has_any(left, PLACE_NEG) or _has_any(label, PLACE_NEG):
            continue
        if re.search(r"место\s+проведен", left[-40:] + label, re.I):
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
        out.append(Finding("PLACE_OF_BIRTH", span[0], span[1], 0.93, "place_of_birth_rule_v2"))
    return out


# --- citizenship ---
CITIZEN_LABEL_RE = re.compile(
    r"(?:"
    r"гражданство(?:\s+клиента)?"
    r"|citizen(?:ship)?"
    r")"
    r"\s*[:\-—–]?\s*"
    r"|"
    r"гражданин(?:ка)?\s+",
    re.IGNORECASE,
)
CITIZEN_VALUE_RE = re.compile(
    r"(?:"
    r"РФ"
    r"|Российская\s+Федерация"
    r"|Росси[яи]"
    r"|[А-ЯЁ][а-яё]+(?:стана|ской|ии|ия)?"
    r"|[A-Z][A-Za-z]+"
    r")"
)
CITIZEN_NEG = [
    r"не\s+требуется",
    r"не\s+нужн",
    r"правил[ао]\s+получен",
    r"получен\w*\s+гражданств",
    r"порядок\s+получен",
    r"условия\s+получен",
    r"опубликован",
    r"справочник",
]


def detect_citizenship(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CITIZEN_LABEL_RE.finditer(text):
        left = _left(text, m.start(), ROLE_WINDOW)
        if _has_any(left, CITIZEN_NEG):
            continue
        if re.search(r"получен\w*\s+гражданств|правил\w*.{0,40}гражданств", left, re.I):
            continue
        rest = text[m.end() :]
        vm = CITIZEN_VALUE_RE.match(rest)
        if not vm:
            continue
        s = m.end() + vm.start()
        e = m.end() + vm.end()
        window = text[max(0, m.start() - 20) : e + 40]
        if re.search(r"гражданств\w*.{0,40}не\s+требуется", window, re.I):
            continue
        if re.search(r"не\s+требуется|не\s+нужн", text[e : e + 50], re.I):
            continue
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        out.append(Finding("CITIZENSHIP", span[0], span[1], 0.92, "citizenship_rule_v2"))
    return out


# --- passport issuer ---
ISSUER_ORG_RE = re.compile(
    r"(?:"
    r"(?:ГУ|ОМВД|УВД|МВД|ОВД|ТП|УФМС|УМВД|ГУВД|МФЦ)"
    r"(?:\s+(?:МВД|России|РФ))?"
    r"\s+[А-Яа-яЁёA-Za-z0-9\.\-]+"
    r"(?:[\s]+[А-Яа-яЁёA-Za-z0-9\.\-]+){0,10}"
    r")"
)
ISSUER_LABEL_RE = re.compile(
    r"(?:"
    r"кем\s+выдан\s+паспорт"
    r"|паспорт\s+выдан"
    r"|орган(?:ом)?\s+выдач\w*(?:\s+паспорт\w*)?"
    r"|выдавш\w*\s+орган"
    r"|;\s*выдан"
    r"|выдан"
    r")"
    r"\s*[:\-—–]?\s*",
    re.IGNORECASE,
)
ISSUER_NEG = [
    r"справочник",
    r"новость",
    r"опубликован",
    r"реестр\s+организац",
    r"список\s+организац",
    r"указано\s+в",
]


def detect_passport_issuer(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in ISSUER_LABEL_RE.finditer(text):
        labeled = m.group(0)
        left = _left(text, m.start(), ROLE_WINDOW)
        if re.fullmatch(r"(?i)выдан\s*[:\-—–]?\s*", labeled):
            if not _has_any(left, [r"паспорт", r"анкет", r"документ"]):
                continue
        if _has_any(left, ISSUER_NEG):
            continue
        if _has_any(_right(text, m.end(), 80), [r"справочник", r"указано\s+в\s+справочник"]):
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
        ctx = _window(text, span[0], span[1], ROLE_WINDOW)
        if _has_any(ctx, ISSUER_NEG) and not _has_any(
            ctx, [r"паспорт\s+выдан", r"кем\s+выдан", r"орган\s+выдач"]
        ):
            continue
        out.append(Finding("PASSPORT_ISSUER", span[0], span[1], 0.94, "passport_issuer_rule_v2"))
    return out


# --- cardholder ---
CARDHOLDER_LABEL_RE = re.compile(
    r"(?:"
    r"имя\s+держателя\s+карты"
    r"|держател\w*\s+карты"
    r"|имя\s+на\s+карт\w*"
    r"|embossed\s+name"
    r"|name\s+on\s+card"
    r"|cardholder(?!\s+company)(?:\s+name)?"
    r")"
    r"\s*[:\-—–]?\s*",
    re.IGNORECASE,
)
CARDHOLDER_VALUE_RE = re.compile(rf"(?:{_LAT_FIO}|{_RU_FIO_2_3})")
CARDHOLDER_NEG = [
    r"докладчик",
    r"спикер",
    r"автор",
    r"поэт",
    r"писател",
    r"company",
    r"компани",
    r"организац",
    r"модератор",
]


def detect_cardholder_name(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARDHOLDER_LABEL_RE.finditer(text):
        left = _left(text, m.start(), ROLE_WINDOW)
        if _has_any(left + m.group(0), CARDHOLDER_NEG):
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
        from app.pii.parts import split_cardholder_span

        out.extend(split_cardholder_span(text, span[0], span[1], 0.94, "cardholder_rule_v2"))
    return out


# --- person (ФИО) ---
PERSON_LABEL_RE = re.compile(
    r"(?:"
    r"ФИО(?:\s+клиента)?"
    r"|ф\.?\s*и\.?\s*о\.?"
    r"|фамилия\s*,?\s*имя(?:\s*и?\s*отчество)?"
    r"|полное\s+имя(?:\s+клиента)?"
    r"|full\s*name"
    r"|customer\s*name"
    r"|client\s*name"
    r")"
    r"\s*[:\-—–]?\s*",
    re.IGNORECASE,
)
PERSON_VALUE_RE = re.compile(
    rf"(?:{_RU_FIO_LOOSE}|{_LAT_FIO})"
)
# Inflected role words: клиенту / клиента / клиентом …
_PERSON_ROLE_WORD = (
    r"клиент\w*|заявител\w*|пользовател\w*|"
    r"заёмщик\w*|заемщик\w*|вкладчик\w*"
)
PERSON_CLIENT_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z])"
    rf"(?i:{_PERSON_ROLE_WORD})"
    rf"\s*[:\-—–]?\s*"
    rf"[«\"']?\s*"
    rf"({_RU_FIO_2_3}|{_LAT_FIO})"
    rf"\s*[»\"']?"
    rf"(?=[\s,.;:!?»\"']|$)"
)
# Free-text contact: capitalised name(s)
PERSON_CONTACT_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z])"
    rf"(?i:"
    rf"свяжит(?:есь|еся)\s+с"
    rf"|свяжись\s+с"
    rf"|напиш(?:и|ите)\s+(?:письмо\s+)?(?:для\s+)?"
    rf"|письмо\s+(?:для\s+)?"
    rf"|позвонит(?:е|ь)\s+(?:клиент\w*\s+)?"
    rf"|передайте\s+"
    rf")"
    rf"\s*"
    rf"({_RU_FIO_1_3})"
    rf"(?=[\s,.;:!?»\"']|$)"
)

# Import shared typo-tolerant self-ID cues — used below
# (PERSON_SELF_CUE_* imported at module top)

PERSON_CALLED_RE = re.compile(
    rf"(?i:{PERSON_SELF_CUE_FOR_RULES})"
    rf"\s*[:\-—–]?\s+"
    rf"({_RU_FIO_1_3_LOOSE})"
    rf"(?=[\s,.;:!?»\"']|$)"
)
# Spoken / inverted: «Ваня Дмитриенко меня зовут» (+ typos)
PERSON_CALLED_FRONT_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z])"
    rf"({_RU_FIO_LOOSE})"
    rf"\s*[,.!?…]?\s*"
    rf"(?i:{PERSON_SELF_CUE_FRONT_FOR_RULES})"
    rf"(?=[\s,.;:!?»\"']|$)"
)# Lead FIO + banking action without «клиент» label
PERSON_BANKING_LEAD_RE = re.compile(
    rf"(?:^|(?<=[.!?…\n]\s)|(?<=\n))"
    rf"({_RU_FIO_2_3})"
    rf"(?=[\s,.;:!?»\"']|$)"
)
PERSON_JSON_CUSTOMER_RE = re.compile(
    r'"customer"\s*:\s*\{[^{}]*?"name"\s*:\s*"([^"]+)"',
    re.IGNORECASE | re.DOTALL,
)
# After bare «я …» / loose FIO reject verbs / fillers mistaken for names
_YA_NAME_STOP = frozenset(
    {
        "хочу",
        "могу",
        "буду",
        "был",
        "была",
        "было",
        "были",
        "есть",
        "живу",
        "живём",
        "живем",
        "работаю",
        "пишу",
        "звоню",
        "иду",
        "еду",
        "смотрю",
        "думаю",
        "знаю",
        "вижу",
        "сейчас",
        "здесь",
        "просто",
        "очень",
        "только",
        "уже",
        "ещё",
        "еще",
        "тут",
        "там",
        "не",
        "на",
        "в",
        "к",
        "по",
        "из",
        "от",
        "для",
        "про",
        "это",
        "тот",
        "эта",
        "этот",
        "зовут",
        "завут",
        "просит",
        "прошу",
        "хочет",
        "можно",
        "нужно",
        "надо",
    }
)


def _trim_fio_stop_tokens(text: str, start: int, end: int) -> tuple[int, int] | None:
    """Drop trailing non-name tokens swallowed by loose FIO («… на», «… просит»)."""
    raw = text[start:end]
    parts = raw.split()
    while len(parts) > 1 and parts[-1].lower().replace("ё", "е") in _YA_NAME_STOP:
        parts.pop()
    if not parts:
        return None
    if parts[0].lower().replace("ё", "е") in _YA_NAME_STOP:
        return None
    kept = " ".join(parts)
    # Re-locate kept substring inside original span (preserve offsets)
    rel = raw.find(kept)
    if rel < 0:
        return None
    return start + rel, start + rel + len(kept)
PERSON_NEG = [
    r"ооо\s*«",
    r"компани",
    r"менеджер",
    r"@",
    r"докладчик",
    r"спикер",
    r"автор\s+книг",
]
PERSON_CULTURAL_NEG = [
    r"поэт",
    r"писател",
    r"роман",
    r"стих",
    r"произведен",
    r"классик",
]


def _person_cultural_block(text: str, start: int, end: int) -> bool:
    return _has_any(_window(text, start, end, ROLE_WINDOW), PERSON_CULTURAL_NEG)


def _ya_stopword_span(text: str, start: int, end: int) -> bool:
    first = text[start:end].split()[0].lower().replace("ё", "е") if start < end else ""
    return first in _YA_NAME_STOP


def detect_person_labelled(text: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[tuple[int, int]] = set()

    def _add(s: int, e: int, score: float, det: str, *, from_ya: bool = False) -> None:
        if any(not (e <= a or s >= b) for a, b in covered):
            return
        trimmed = _trim_fio_stop_tokens(text, s, e)
        if not trimmed:
            return
        s, e = trimmed
        if from_ya and _ya_stopword_span(text, s, e):
            return
        if _has_any(_left(text, s, 40), PERSON_NEG):
            return
        if _person_cultural_block(text, s, e):
            return
        span = _trim_value_span(text, s, e)
        if not span:
            return
        covered.add(span)
        from app.pii.parts import split_person_span

        out.extend(split_person_span(text, span[0], span[1], score, det))

    for m in PERSON_LABEL_RE.finditer(text):
        rest = text[m.end() :]
        vm = PERSON_VALUE_RE.match(rest)
        if not vm:
            continue
        _add(m.end() + vm.start(), m.end() + vm.end(), 0.97, "person_label_rule_v2")

    for m in PERSON_JSON_CUSTOMER_RE.finditer(text):
        _add(m.start(1), m.end(1), 0.95, "person_json_customer_v2")

    for regex, score, det in (
        (PERSON_CLIENT_RE, 0.9, "person_role_rule_v2"),
        (PERSON_CONTACT_RE, 0.88, "person_contact_rule_v2"),
        (PERSON_CALLED_FRONT_RE, 0.92, "person_called_front_rule_v2"),
    ):
        for m in regex.finditer(text):
            _add(m.start(1), m.end(1), score, det)

    for m in PERSON_CALLED_RE.finditer(text):
        cue = m.group(0)[: m.start(1) - m.start()]
        from_ya = bool(re.search(r"(?i)(?<![А-Яа-яЁёA-Za-z0-9])я\s*[:\-—–]?\s*$", cue))
        _add(m.start(1), m.end(1), 0.92, "person_called_rule_v2", from_ya=from_ya)

    # «Иван Петров хочет оформить карту» — capital FIO + real banking intent
    from app.pii.claims import has_banking_intent

    if has_banking_intent(text, include_generic=False):
        for m in PERSON_BANKING_LEAD_RE.finditer(text):
            _add(m.start(1), m.end(1), 0.85, "person_banking_lead_v2")

    return out


# Cloud.ru pii.fio-ru idea: patronymic suffix as precision anchor.
# ONLY emits candidates — discourse gate decides personal vs third-party.
_PATRONYMIC = r"(?:ич(?:а|у|ем|е)?|вн(?:а|ы|е|у|ой)|ичн(?:а|ы|е|у|ой))"
PERSON_PATRONYMIC_RE = re.compile(
    rf"(?:^|[^\wА-Яа-яЁё])"
    rf"("
    rf"(?:{_RU_NAME}(?:-{_RU_NAME})?\s+{_RU_NAME}\s+{_RU_NAME}{_PATRONYMIC})"
    rf"|(?:{_RU_NAME}\s+{_RU_NAME}{_PATRONYMIC}\s+{_RU_NAME}(?:-{_RU_NAME})?)"
    rf")"
    rf"(?:[^\wА-Яа-яЁё]|$)"
)


def detect_person_patronymic(text: str) -> list[Finding]:
    """FIO with -ич/-вна patronymic. Discourse filter_findings still applies."""
    out: list[Finding] = []
    for m in PERSON_PATRONYMIC_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if _person_cultural_block(text, s, e):
            continue
        if _has_any(_left(text, s, 40), PERSON_NEG):
            continue
        # Skip company titles «ООО „…“»
        left40 = _left(text, s, 40)
        if re.search(r"(?i)(?:ооо|ао|пао|зао|ип)\s*[«\"']?\s*$", left40):
            continue
        span = _trim_value_span(text, s, e)
        if not span:
            continue
        from app.pii.parts import split_person_span

        out.extend(split_person_span(text, span[0], span[1], 0.88, "person_patronymic_v1"))
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
    detect_snils,
    detect_international_passport,
    detect_oms,
    detect_place_of_birth,
    detect_citizenship,
    detect_passport_issuer,
    detect_cardholder_name,
    detect_person_labelled,
    detect_person_patronymic,
]


def detect_all_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for detector in RULE_DETECTORS:
        findings.extend(detector(text))
    return findings
