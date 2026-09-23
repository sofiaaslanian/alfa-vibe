"""Personal-claim cues + banking-request intent catalog.

No celebrity lists. No LLM.
Covers spoken order, colloquial forms, and common typos via character classes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── typo-tolerant atoms ────────────────────────────────────────────────────
# з[оа]в[уы]т ≈ зовут / завут / зовыт
_ZOVUT = r"з[оа]в[уы]т"
_MENYA = r"мен[яа]"
_MOE = r"мо[её]"
_IMYA = r"им[яа]"
_FIO = r"(?:фио|ф\.?\s*и\.?\s*о\.?)"
_KLIENT = r"кли[еэ]нт\w*"
_USER = r"пользовател\w*"

# ── Self-ID cue fragments (shared by rules + discourse) ────────────────────
# Claim BEFORE the name («меня зовут X»)
SELF_ID_BEFORE_PATTERNS: tuple[str, ...] = (
    rf"{_MENYA}\s+{_ZOVUT}",
    rf"{_ZOVUT}\s+{_MENYA}",
    rf"{_MOE}\s+{_IMYA}",
    rf"это\s+{_MOE}\s+{_IMYA}",
    r"представл(?:юсь|яюсь|ение)",
    r"разрешите\s+представ",
    r"знаком(?:ьтесь|ство)[,:]?\s*я",
    r"я\s+[-—–]",
    r"я\s+(?:есть|являюсь)",
    r"(?<![А-Яа-яЁёA-Za-z0-9])я",
    r"мо[яей]\s+фамил",
    r"мо[её]\s+отчеств",
    rf"{_KLIENT}\s+{_ZOVUT}",
    rf"{_ZOVUT}\s+{_KLIENT}",
    rf"{_USER}\s+{_ZOVUT}",
    rf"имя\s+{_KLIENT}",
    r"пишите\s+(?:мне\s+)?(?:как|на\s+имя)",
    r"обраща(?:йтесь|юсь)\s+(?:ко?\s+мне\s+)?как",
)

# Claim AFTER the name («X меня зовут»)
SELF_ID_AFTER_PATTERNS: tuple[str, ...] = (
    rf"{_MENYA}\s+{_ZOVUT}",
    rf"{_ZOVUT}\s+{_MENYA}",
    rf"{_MOE}\s+{_IMYA}",
    rf"{_ZOVUT}",
    rf"так\s+{_MENYA}\s+{_ZOVUT}",
    rf"вот\s+так\s+{_ZOVUT}",
)

KYC_FIELD_PATTERNS: tuple[str, ...] = (
    rf"{_FIO}(?:\s+{_KLIENT})?",
    r"фамилия\s*,?\s*имя(?:\s*и?\s*отчество)?",
    r"полное\s+имя(?:\s+клиента)?",
    r"заявитель",
    r"за[её]мщик",
    r"вкладчик",
    r"имя\s+клиента",
    r'"\s*name\s*"\s*:',
    r"holder[_\s-]?name",
    r"full[_\s-]?name",
    r"customer[_\s-]?name",
    r"client[_\s-]?name",
)

CLIENT_ROLE_PATTERNS: tuple[str, ...] = (
    r"клиент\w*",
    r"пользовател\w*",
    r"заявител\w*",
    r"за[её]мщик\w*",
    r"вкладчик\w*",
)


def _or_group(parts: tuple[str, ...]) -> str:
    return "(?:" + "|".join(parts) + ")"


SELF_ID_BEFORE_RE = re.compile(
    rf"(?i){_or_group(SELF_ID_BEFORE_PATTERNS)}.{{0,48}}$"
)
SELF_ID_AFTER_RE = re.compile(
    rf"(?i)^\s*[,.!?…:;]?\s*{_or_group(SELF_ID_AFTER_PATTERNS)}\b"
)
KYC_FIELD_RE = re.compile(rf"(?i){_or_group(KYC_FIELD_PATTERNS)}.{{0,80}}$")
CLIENT_ROLE_RE = re.compile(
    rf"(?i)(?<![А-Яа-яЁёA-Za-z]){_or_group(CLIENT_ROLE_PATTERNS)}"
    r"\s*[:\-—–]?\s*[«\"']?\s*$"
)

# Cue used inside person detector regexes (name AFTER cue)
PERSON_SELF_CUE_FOR_RULES = _or_group(
    (
        # Longer / specific first — avoid bare «зовут» swallowing «меня»
        rf"{_ZOVUT}\s+{_MENYA}",
        rf"{_MENYA}\s+{_ZOVUT}",
        rf"{_ZOVUT}\s+клиента",
        rf"клиента?\s+{_ZOVUT}",
        rf"{_USER}\s+{_ZOVUT}",
        rf"{_MOE}\s+{_IMYA}",
        r"имя\s+клиента",
        r"представл(?:юсь|яюсь)",
        r"я\s+[-—–]",
        r"я\s+(?:есть|являюсь)",
        r"(?<![А-Яа-яЁёA-Za-z0-9])я",
        r"мо[яей]\s+фамил",
        rf"{_ZOVUT}",  # bare last
    )
)
# Name BEFORE cue
PERSON_SELF_CUE_FRONT_FOR_RULES = _or_group(
    (
        rf"{_MENYA}\s+{_ZOVUT}",
        rf"{_ZOVUT}\s+{_MENYA}",
        rf"{_MOE}\s+{_IMYA}",
        r"так\s+меня\s+зовут",
    )
)


# ── Banking request intents ────────────────────────────────────────────────
@dataclass(frozen=True)
class BankingIntent:
    id: str
    label: str
    pattern: re.Pattern[str]


def _intent(iid: str, label: str, *alts: str) -> BankingIntent:
    body = "|".join(f"(?:{a})" for a in alts)
    return BankingIntent(iid, label, re.compile(rf"(?i)(?:{body})"))


BANKING_INTENTS: tuple[BankingIntent, ...] = (
    _intent(
        "card_issue",
        "выпуск / заказ карты",
        r"хочу\s+(?:заказать|оформить|получить|выпустить)\s+карт",
        r"(?:заказать|оформить|выпустить|открыть)\s+карт",
        r"заказ\w*\s+карт",
        r"оформлен\w*\s+карт",
        r"выпуск\w*\s+карт",
        r"новая\s+карт",
        r"карту\s+пожалуйста",
        r"нужна\s+(?:дебетов\w*\s+|кредитн\w*\s+)?карт",
        r"хочу\s+карт",
    ),
    _intent(
        "card_reissue",
        "перевыпуск карты",
        r"перевыпуст\w*",
        r"перевыпуск\w*",
        r"замен\w*\s+карт",
        r"восстанов\w*\s+карт",
        r"повторн\w*\s+выпуск\w*\s+карт",
        r"карт\w*\s+(?:утерян|потерял|украл|сломал|истек|истекл)",
        r"(?:утерял|потерял|украли|сломан)\w*\s+карт",
    ),
    _intent(
        "card_block",
        "блокировка карты",
        r"заблок\w*\s+карт",
        r"блок\w*\s+карт",
        r"карт\w*\s+заблок",
        r"стоп\s+карт",
        r"заморозь?те?\s+карт",
    ),
    _intent(
        "card_unblock",
        "разблокировка карты",
        r"разблок\w*\s+карт",
        r"разморозь?те?\s+карт",
        r"включите\s+карт",
    ),
    _intent(
        "card_pin",
        "PIN / код карты",
        r"(?:смен|измен|восстанов|напомн|забыл)\w*\s+(?:пин|pin|код\s+карт)",
        r"(?:пин|pin)[\-\s]?код",
        r"код\s+от\s+карт",
    ),
    _intent(
        "account_open",
        "открытие счёта",
        r"открыть\s+сч[её]т",
        r"открыти\w*\s+сч[её]т",
        r"завести\s+сч[её]т",
        r"новый\s+сч[её]т",
    ),
    _intent(
        "account_close",
        "закрытие счёта",
        r"закрыть\s+сч[её]т",
        r"закрыти\w*\s+сч[её]т",
        r"расторгн\w*\s+договор",
    ),
    _intent(
        "credit",
        "кредит / заём",
        r"хочу\s+(?:кредит|за[её]м)",
        r"(?:оформить|взять|получить)\s+(?:кредит|за[её]м)",
        r"кредитн\w*\s+(?:карт|лимит|заявк)",
        r"потребительск\w*\s+кредит",
        r"заявк\w*\s+на\s+кредит",
    ),
    _intent(
        "mortgage",
        "ипотека",
        r"ипотек\w*",
        r"жилищн\w*\s+кредит",
    ),
    _intent(
        "transfer",
        "перевод",
        r"перевод\w*",
        r"перевест\w*",
        r"отправ\w*\s+деньг",
        r"swift|сеп[аa]|sbp|сбп",
        r"по\s+номеру\s+телефон\w*\s+перевод",
    ),
    _intent(
        "payment",
        "платёж / оплата",
        r"оплат\w*",
        r"плат[её]ж\w*",
        r"погаси\w*\s+(?:долг|кредит|задолжен)",
        r"коммуналк\w*",
    ),
    _intent(
        "limit",
        "лимит",
        r"(?:увелич|уменьш|смен|измен)\w*\s+лимит",
        r"лимит\w*\s+(?:по\s+)?карт",
        r"кредитн\w*\s+лимит",
    ),
    _intent(
        "statement",
        "выписка / справка",
        r"выписк\w*",
        r"справк\w*\s+(?:об?\s+)?(?:остат|сч[её]т|доход|задолж)",
        r"остаток\s+на\s+сч[её]т",
        r"баланс\s+карт",
    ),
    _intent(
        "callback",
        "перезвон / связь",
        r"перезвон\w*",
        r"свяж\w*",
        r"наберите\s+мне",
        r"позвоните\s+мне",
        r"жду\s+звонк",
        r"обратн\w*\s+связ",
    ),
    _intent(
        "support",
        "поддержка / жалоба",
        r"помощ\w*",
        r"поддержк\w*",
        r"жалоб\w*",
        r"не\s+работает",
        r"проблема\s+с\s+карт",
        r"спорн\w*\s+операц",
        r"чарджбэк|chargeback",
    ),
    _intent(
        "status",
        "статус заявки",
        r"статус\s+заявк",
        r"когда\s+будет\s+(?:готов|карт|решен)",
        r"где\s+моя\s+(?:карт|заявк)",
        r"отслеж\w*\s+заявк",
    ),
    _intent(
        "passport_update",
        "обновление паспортных данных",
        r"обнов\w*\s+(?:паспорт|данн)",
        r"смен\w*\s+паспорт",
        r"новые\s+паспортн",
    ),
    _intent(
        "generic_request",
        "общая клиентская просьба",
        r"\bпросит\b",
        r"\bпрошу\b",
        r"\bхочу\b",
        r"\bнужно\b",
        r"\bнадо\b",
        r"пожалуйста",
        r"можете\s+(?:ли\s+)?",
        r"сделайте",
        r"оформите",
        r"помогите",
    ),
)


def classify_banking_intents(text: str) -> list[str]:
    """Return intent ids found in text (may be multiple)."""
    found: list[str] = []
    for intent in BANKING_INTENTS:
        if intent.pattern.search(text):
            found.append(intent.id)
    return found


def has_banking_intent(text: str, *, include_generic: bool = True) -> bool:
    ids = classify_banking_intents(text)
    if not include_generic:
        ids = [i for i in ids if i != "generic_request"]
    return bool(ids)


def banking_intent_labels(text: str) -> list[str]:
    ids = set(classify_banking_intents(text))
    return [i.label for i in BANKING_INTENTS if i.id in ids]


# ── Address discourse (personal home vs public/service place) ───────────────
# Not a landmark dictionary — personal claim vs public framing.

ADDRESS_PERSONAL_CUES: tuple[str, ...] = (
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
    r"доставьте",
    r"принесите",
    r"привезйте",
    r"по\s+адрес[уа]",
    r"отправьте\s+(?:на|по)",
    r"корреспонденц",
)

ADDRESS_PUBLIC_CUES: tuple[str, ...] = (
    r"отделен\w*",
    r"филиал",
    r"офис",
    r"адрес\s+банк",
    r"адрес\s+отделен",
    r"магазин",
    r"торговый\s+центр",
    r"\bтц\b",
    r"ресторан",
    r"кафе",
    r"клуб",
    r"музей",
    r"театр",
    r"стадион",
    r"аэропорт",
    r"вокзал",
    r"метро\b",
    r"остановк",
    r"встретимся",
    r"встреча",
    r"свидани",
    r"находится",
    r"расположен",
    r"штаб[\-\s]?квартир",
    r"склад",
    r"пвз\b",
    r"пункт\s+выдач",
    r"юридическ\w*\s+адрес",
    r"\bооо\b",
    r"работаю",
    r"работ[аые]\s+по\s+адрес",
    r"достопримечател",
)

ADDRESS_PERSONAL_RE = re.compile(rf"(?i){_or_group(ADDRESS_PERSONAL_CUES)}")
ADDRESS_PUBLIC_RE = re.compile(rf"(?i){_or_group(ADDRESS_PUBLIC_CUES)}")


# ── INN discourse ──────────────────────────────────────────────────────────
INN_PERSONAL_CUES: tuple[str, ...] = (
    r"\bинн\b",
    r"мой\s+инн",
    r"инн\s+клиента",
    r"инн\s+физлиц",
    r"идентификационн\w*\s+номер\s+налогоплательщик",
    r"\binn\b",
    r"taxpayer",
)
INN_PUBLIC_CUES: tuple[str, ...] = (
    r"номер\s+заказ",
    r"заказ[ае]?\s*№",
    r"номер\s+договор",
    r"номер\s+заявк",
    r"номер\s+сч[её]т",
    r"id\s+операц",
    r"идентификатор\s+операц",
    r"артикул",
    r"серийн\w*",
    r"штрих[\-\s]?код",
    r"tracking",
    r"трек[\-\s]?номер",
    r"номер\s+посылк",
)
INN_PERSONAL_RE = re.compile(rf"(?i){_or_group(INN_PERSONAL_CUES)}")
INN_PUBLIC_RE = re.compile(rf"(?i){_or_group(INN_PUBLIC_CUES)}")
