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
    if _looks_like_full_patronymic_fio(text[start:end]) and CONTACT_AFTER_RE.search(right):
        return True
    return contact or banking_strong or client or claim


def should_skip_person(text: str, start: int, end: int) -> bool:
    """True → drop PERSON finding."""
    return not is_personal_person_mention(text, start, end)


ADDRESS_STRONG_PERSONAL_RE = re.compile(
    r"(?i)(?:"
    r"\bживу\b|\bжив[её]м\b|прожива|прописан|зарегистрирован"
    r"|мой\s+адрес|наш\s+адрес|домашн\w*\s+адрес"
    r"|адрес\s+(?:проживани|регистрац|клиента|для\s+корреспонденц|доставк)"
    r"|доставьте|принесите|привез\w*|отправьте\s+(?:на|по)"
    r")"
)


def is_personal_address_mention(text: str, start: int, end: int) -> bool:
    """Personal home/delivery address vs public/service place.

    Public/service framing wins over generic location syntax such as
    «по адресу». Only an explicit owner/delivery cue can override it.
    """
    from app.pii.claims import ADDRESS_PERSONAL_RE, ADDRESS_PUBLIC_RE

    left = _left(text, start)
    ctx = _ctx(text, start, end)
    value = text[start:end]
    strong_personal = bool(
        ADDRESS_STRONG_PERSONAL_RE.search(left)
        or ADDRESS_STRONG_PERSONAL_RE.search(ctx)
    )
    personal = bool(ADDRESS_PERSONAL_RE.search(left) or ADDRESS_PERSONAL_RE.search(ctx))
    public = bool(ADDRESS_PUBLIC_RE.search(left) or ADDRESS_PUBLIC_RE.search(ctx))

    if public and not strong_personal:
        return False
    if strong_personal:
        return True
    if personal and not public:
        return True
    if re.search(r"(?i)адрес", left):
        return not public
    # Structured street address without public cue — keep (format-context)
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

EMAIL_PERSONAL_RE = re.compile(
    r"(?i)(?:"
    r"email\s+клиент|e-?mail\s+клиент|почт\w*\s+клиент"
    r"|мо[яей]\s+(?:почт|email|e-?mail)|личн\w*\s+(?:почт|email|e-?mail)"
    r"|контакт\w*\s+клиент"
    r")"
)
NON_PERSONAL_TEMPLATE_RE = re.compile(
    r"(?i)(?:"
    r"пример|шаблон|образец|placeholder|документац|инструкц|тестов\w*\s+данн"
    r")"
)
PUBLIC_CONTACT_ROLE_RE = re.compile(
    r"(?i)(?:"
    r"офис|отделен\w*|филиал|банк\w*|колл[\-\s]?центр|call[\-\s]?center"
    r"|горяч\w*\s+лини|служб\w*\s+поддержк|контакт[-\s]?центр"
    r"|публичн\w*\s+номер|служебн\w*\s+(?:телефон|контакт|почт)"
    r")"
)
TECHNICAL_IDENTIFIER_ROLE_RE = re.compile(
    r"(?i)(?:"
    r"серийн\w*\s+номер|инвентарн\w*\s+номер"
    r"|код\s+(?:партии|товара|операции|записи|заказа|заявки)"
    r"|номер\s+(?:заказа|договора|заявки|сч[её]та|посылки)"
    r"|артикул|штрих[\-\s]?код|tracking|трек[\-\s]?номер|imei"
    r")"
)
PAYMENT_CARD_PERSONAL_RE = re.compile(
    r"(?i)(?:"
    r"номер\s+карт|карт[аы]\s+(?:клиент|заявител)|мо[яей]\s+карт"
    r"|\bpan\b|visa|mastercard|master[\-\s]?card|\bмир\b|оплат\w*\s+карт"
    r")"
)


def is_personal_phone_mention(text: str, start: int, end: int) -> bool:
    """Keep personal phones; drop public/service contact roles."""
    from app.pii.public_contacts import (
        has_service_phone_context,
        is_public_service_phone,
    )

    value = text[start:end]
    ctx = _ctx(text, start, end, 120)
    personal = bool(PHONE_PERSONAL_RE.search(ctx))
    if is_public_service_phone(value):
        return False
    if PUBLIC_CONTACT_ROLE_RE.search(ctx) and not personal:
        return False
    if has_service_phone_context(text, start, end) and not personal:
        return False
    return True


def should_skip_phone(text: str, start: int, end: int) -> bool:
    return not is_personal_phone_mention(text, start, end)


def is_personal_email_mention(text: str, start: int, end: int) -> bool:
    """A syntactically valid email is PII unless context marks a template/service role."""
    ctx = _ctx(text, start, end, 120)
    personal = bool(EMAIL_PERSONAL_RE.search(ctx))
    if NON_PERSONAL_TEMPLATE_RE.search(ctx) and not personal:
        return False
    if PUBLIC_CONTACT_ROLE_RE.search(ctx) and not personal:
        return False
    return True


def should_skip_email(text: str, start: int, end: int) -> bool:
    return not is_personal_email_mention(text, start, end)


def is_personal_payment_card_mention(text: str, start: int, end: int) -> bool:
    """Luhn/shape proves a PAN candidate, while role decides whether it is a card."""
    ctx = _ctx(text, start, end, 120)
    personal = bool(PAYMENT_CARD_PERSONAL_RE.search(ctx))
    if TECHNICAL_IDENTIFIER_ROLE_RE.search(ctx) and not personal:
        return False
    return True


def should_skip_payment_card(text: str, start: int, end: int) -> bool:
    return not is_personal_payment_card_mention(text, start, end)


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
