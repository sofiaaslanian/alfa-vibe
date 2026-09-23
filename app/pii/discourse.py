"""Discourse-role gate for PERSON findings.

Uses claim catalogs from app.pii.claims (self-ID + banking intents).
No celebrity lexicon. No LLM. Hot path = regex over local windows.
"""

from __future__ import annotations

import re

from app.pii.claims import (
    CLIENT_ROLE_RE,
    KYC_FIELD_RE,
    SELF_ID_AFTER_RE,
    SELF_ID_BEFORE_RE,
    has_banking_intent,
)

WINDOW = 120

# Third-party / narrative / cultural mention cues.
THIRD_PARTY_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bон\b|\bона\b|\bего\b|\bе[её]\b|\bим\b|\bэтот\b|\bэта\b|\bтого\b|"
    r"сказал|заявил|отметил|написал|купил|продал|основал|возглавил|"
    r"родился\s+в\s+\d|умер|жил\s+в|"
    r"поэт|писател|романист|драматург|классик|стих|"
    r"актер|актёр|актриса|режиссер|режиссёр|певец|певица|музыкант|блогер|"
    r"миллиардер|миллионер|основател|соосновател|\bceo\b|\bcto\b|"
    r"президент|премьер|министр|сенатор|депутат|корол[ья]|император|"
    r"чемпион|футболист|хоккеист|теннисист|"
    r"известный|знаменит|легендарн|популярн|зв[её]зд|"
    r"тикток|ютуб|youtube|instagram|инстаграм|"
    r"роман\s+[«\"]|произведен|биограф|энциклопед|википед|"
    r"\btesla\b|\bspacex\b|\bopenai\b|\btwitter\b|\bx\.com\b"
    r")"
)

APPOSITION_RE = re.compile(r"^\s*[—–\-]\s*\S+")

# Imperative / contact framing: the named person is still PII in the request.
CONTACT_BEFORE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"свяжит(?:есь|еся)\s+с"
    r"|свяжись\s+с"
    r"|напиш(?:и|ите)(?:\s+письмо)?"
    r"|письмо\s+(?:для)?"
    r"|позвонит(?:е|ь)"
    r"|передайте"
    r"|для"
    r")"
    r"\s*[:\-]?\s+$"
)

CONTACT_AFTER_RE = re.compile(
    r"(?i)^\s*[,;:—–-]?\s*"
    r"(?:тел(?:ефон)?\.?|мобильн\w*|email|e-?mail|почт[аы]?|мейл)"
    r"\s*[:.]?"
)
_PATRONYMIC_TOKEN_RE = re.compile(
    r"(?i)(?:ич(?:а|у|ем|е)?|вн(?:а|ы|е|у|ой)|ичн(?:а|ы|е|у|ой))$"
)

# Narrative continuation right after a full FIO: the named person is being
# described as a third party («… пришёл в банк», «… любит кофе»), not the
# data subject. A bare FIO with nothing after it stays personal.
_NARRATIVE_AFTER_RE = re.compile(
    r"(?i)^\s*[,;:—–-]?\s*"
    r"(?:приш[её]л|пришл[аи]|любит|работает|жив[её]т|учится|читает|"
    r"сказал|заявил|отметил|написал|купил|продал|основал|возглавил|"
    r"родился|умер|стал|был|была|ходил|ходила|поехал|поехала)"
    r"\b"
)


def _looks_like_full_patronymic_fio(value: str) -> bool:
    tokens = value.split()
    return len(tokens) == 3 and any(_PATRONYMIC_TOKEN_RE.search(token) for token in tokens)


def _left(text: str, start: int, size: int = WINDOW) -> str:
    return text[max(0, start - size) : start]


def _right(text: str, end: int, size: int = WINDOW) -> str:
    return text[end : min(len(text), end + size)]


def _ctx(text: str, start: int, end: int, size: int = WINDOW) -> str:
    return text[max(0, start - size) : min(len(text), end + size)]


def has_kyc_or_self_claim(text: str, start: int, end: int) -> bool:
    left = _left(text, start)
    right = _right(text, end, 48)
    return bool(
        KYC_FIELD_RE.search(left)
        or SELF_ID_BEFORE_RE.search(left)
        or SELF_ID_AFTER_RE.search(right)
        or CLIENT_ROLE_RE.search(left)
    )


def has_third_party_discourse(text: str, start: int, end: int) -> bool:
    ctx = _ctx(text, start, end)
    return bool(
        THIRD_PARTY_RE.search(ctx)
        or APPOSITION_RE.search(_right(text, end, 40))
    )


def is_personal_person_mention(text: str, start: int, end: int) -> bool:
    """True → keep PERSON finding as personal data."""
    left = _left(text, start)
    right = _right(text, end, 100)
    claim = has_kyc_or_self_claim(text, start, end)
    third = has_third_party_discourse(text, start, end)
    client = bool(CLIENT_ROLE_RE.search(left))
    self_id = bool(
        KYC_FIELD_RE.search(left)
        or SELF_ID_BEFORE_RE.search(left)
        or SELF_ID_AFTER_RE.search(right)
    )
    banking = has_banking_intent(right) or has_banking_intent(
        _ctx(text, start, end, 160)
    )
    banking_strong = has_banking_intent(text, include_generic=False)
    contact = bool(CONTACT_BEFORE_RE.search(left))

    if self_id:
        return True
    if client and banking:
        return True
    if third:
        return False
    # Full FIO with patronymic (last + first + patronymic) is personal data
    # even without an explicit role cue, unless it continues into a third-party
    # narrative («… пришёл в банк», «… любит кофе»). Two-part names still need
    # context so celebrity/third-party mentions stay clear.
    if _looks_like_full_patronymic_fio(text[start:end]):
        if not _NARRATIVE_AFTER_RE.search(right):
            return True
    if _looks_like_full_patronymic_fio(text[start:end]) and CONTACT_AFTER_RE.search(right):
        return True
    return contact or banking_strong or client or claim


def should_skip_person(text: str, start: int, end: int) -> bool:
    """True → drop PERSON finding."""
    return not is_personal_person_mention(text, start, end)


ADDRESS_STRONG_PERSONAL_RE = re.compile(
    r"(?i)(?:"
    r"мой\s+адрес|наш\s+адрес|домашн\w*\s+адрес"
    r"|адрес\s+(?:проживани|регистрац|клиента|для\s+корреспонденц)"
    r"|живу|жив[её]м|прожива|прописан|зарегистрирован"
    r")"
)


def is_personal_address_mention(text: str, start: int, end: int) -> bool:
    """Personal address vs a public/place locator.

    Address syntax only creates a candidate. Role resolution is separate:
    explicit personal ownership/KYC wins; otherwise an explicit public/place
    subject (office, museum, meeting, shop, etc.) suppresses the candidate.
    Generic locator wording such as "по адресу" is intentionally weak.
    """
    from app.pii.claims import ADDRESS_PERSONAL_RE, ADDRESS_PUBLIC_RE

    left = _left(text, start)
    ctx = _ctx(text, start, end)
    value = text[start:end]
    strong_personal = bool(
        ADDRESS_STRONG_PERSONAL_RE.search(left)
        or ADDRESS_STRONG_PERSONAL_RE.search(ctx)
    )
    public = bool(ADDRESS_PUBLIC_RE.search(left) or ADDRESS_PUBLIC_RE.search(ctx))
    personal = bool(ADDRESS_PERSONAL_RE.search(left) or ADDRESS_PERSONAL_RE.search(ctx))

    if strong_personal:
        return True
    if public:
        return False
    if personal:
        return True
    if re.search(r"(?i)адрес", left):
        return True
    # Structured street address without an explicit public cue — keep.
    return bool(
        re.search(r"(?i)(?:ул\.|улиц|пр\.|проспект|проезд|пер\.|ш\.|дом|\bд\.)", value)
    )


def should_skip_address(text: str, start: int, end: int) -> bool:
    return not is_personal_address_mention(text, start, end)


def is_personal_inn_mention(text: str, start: int, end: int) -> bool:
    """Keep valid INN unless the left context marks a non-personal role."""
    from app.pii.claims import INN_PERSONAL_RE, INN_PUBLIC_RE

    _ = end
    left_ctx = _left(text, start)
    return bool(
        INN_PERSONAL_RE.search(left_ctx)
        or not INN_PUBLIC_RE.search(left_ctx)
    )


def should_skip_inn(text: str, start: int, end: int) -> bool:
    return not is_personal_inn_mention(text, start, end)


# ── Phone: personal contact vs bank support / public hotline ───────────────
PHONE_PERSONAL_RE = re.compile(
    r"(?i)(?:"
    r"мой\s+телефон"
    r"|мне\s+(?:на|по)\s+телефон"
    r"|перезвон\w*\s+мне"
    r"|позвоните\s+мне"
    r"|телефон\s+клиента"
    r"|тел\.?\s+клиента"
    r"|мобильн\w*"
    r"|личный\s+телефон"
    r"|связ(?:аться|итесь)\s+со?\s+мной"
    r"|пишите\s+(?:мне|на)\s*(?:в\s+)?(?:whats?app|телеграм|tg)?"
    r"|мой\s+номер"
    r"|номер\s+клиента"
    r")"
)


def is_personal_phone_mention(text: str, start: int, end: int) -> bool:
    """Keep personal phones; drop Alfa hotline / support-desk numbers."""
    from app.pii.public_contacts import (
        has_service_phone_context,
        is_public_service_phone,
    )

    value = text[start:end]
    if is_public_service_phone(value):
        return False
    if has_service_phone_context(text, start, end) and not PHONE_PERSONAL_RE.search(
        text[max(0, start - 100) : end + 40]
    ):
        return False
    return True


def should_skip_phone(text: str, start: int, end: int) -> bool:
    return not is_personal_phone_mention(text, start, end)


# ── Dates: birth vs holiday / event / publication ──────────────────────────
HOLIDAY_OR_EVENT_RE = re.compile(
    r"(?i)(?:"
    r"новый\s+год|новогодн"
    r"|рождеств"
    r"|8\s*марта|международн\w*\s+женск"
    r"|23\s*феврал|дня?\s+защитник"
    r"|9\s*мая|день\s+побед"
    r"|1\s*мая|день\s+труд"
    r"|день\s+народн\w*\s+единств"
    r"|праздник|выходн|каникул|отпуск"
    r"|свадьб|юбиле|корпоратив|концерт|фестивал"
    r"|дедлайн|срок\s+сдач|дата\s+встреч|дата\s+заседани"
    r"|дата\s+публикац|опубликован|дата\s+договор"
    r"|дата\s+заявк|дата\s+отч[её]т"
    r")"
)
BIRTH_CUE_RE = re.compile(
    r"(?i)(?:"
    r"дат[аы]\s+рожден"
    r"|родил(?:ся|ась)"
    r"|\bдр\b"
    r"|день\s+рожден"
    r"|birth[_\s-]?date"
    r"|рожден[ия]?"
    r")"
)


def is_personal_birth_date_mention(text: str, start: int, end: int) -> bool:
    """Birth date of the subject vs holiday / celebrity / publication date."""
    left = _left(text, start, 100)
    ctx = _ctx(text, start, end, 100)
    birth = bool(BIRTH_CUE_RE.search(left) or BIRTH_CUE_RE.search(ctx))
    holiday = bool(HOLIDAY_OR_EVENT_RE.search(ctx))
    third = has_third_party_discourse(text, start, end)
    self_claim = has_kyc_or_self_claim(text, start, end)

    # Holiday / event without an explicit birth cue → not PII
    if holiday and not birth:
        return False
    # «день рождения Пушкина» / news about a celebrity DOB → not client's PII
    if birth and third and not self_claim:
        return False
    # Rules emit BIRTH_DATE only with birth role; keep residual spans
    return True


def should_skip_birth_date(text: str, start: int, end: int) -> bool:
    return not is_personal_birth_date_mention(text, start, end)


def is_personal_place_of_birth_mention(text: str, start: int, end: int) -> bool:
    """Client birth place vs celebrity/history narrative («Пушкин родился в…»)."""
    left = _left(text, start, 100)
    third = has_third_party_discourse(text, start, end)
    self_claim = has_kyc_or_self_claim(text, start, end)
    client_near = bool(
        re.search(
            r"(?i)(?<![А-ЯЁA-Z])(?:клиент\w*|пользовател\w*|заявител\w*)",
            left,
        )
    )

    # Celebrity / biography narrative without KYC → not client PII.
    # Every other PLACE_OF_BIRTH finding is kept by policy.
    return not (third and not self_claim and not client_near)


def should_skip_place_of_birth(text: str, start: int, end: int) -> bool:
    return not is_personal_place_of_birth_mention(text, start, end)
