#!/usr/bin/env python3
"""Reconstructed stage-1 identification eval: 170 cases (5 pos + 5 neg per type).

Reconstructed from docs/STAGE1_IDENTIFICATION_REPORT.md. Positive case passes
when the target type is present among final mask-findings; negative passes when
it is absent. Profile: autotest (hybrid ML + rules).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("NER_ENABLED", "1")
os.environ.setdefault("NER_FAIL_CLOSED", "0")
os.environ.setdefault("STORAGE_BACKEND", "memory")

from app.pii.detect import detect_pii

# (type, text, is_positive)
CASES: list[tuple[str, str, bool]] = [
    # ── PERSON ──────────────────────────────────────────────────────────────
    ("PERSON", "ФИО клиента: Иванов Иван Иванович", True),
    ("PERSON", "Клиент Петрова Анна просит ответить.", True),
    ("PERSON", "меня зовут Соня Асланян", True),
    ("PERSON", "Меня зовут София Асланян", True),
    ("PERSON", "мое имя Иван Петров", True),
    ("PERSON", "Лев Толстой написал «Войну и мир».", False),
    ("PERSON", "Юрий Гагарин первым полетел в космос.", False),
    ("PERSON", "Пётр Чайковский — великий композитор.", False),
    ("PERSON", "Дмитрий Менделеев создал таблицу элементов.", False),
    ("PERSON", "Антон Чехов — русский писатель.", False),
    # ── PLACE_OF_BIRTH ──────────────────────────────────────────────────────
    ("PLACE_OF_BIRTH", "Место рождения: Москва", True),
    ("PLACE_OF_BIRTH", "Клиент родился в Казани.", True),
    ("PLACE_OF_BIRTH", "Место рождения клиента: Санкт-Петербург", True),
    ("PLACE_OF_BIRTH", "Родился в Новосибирске.", True),
    ("PLACE_OF_BIRTH", "Место рождения: Екатеринбург", True),
    ("PLACE_OF_BIRTH", "Юрий Гагарин родился в деревне Клушино.", False),
    ("PLACE_OF_BIRTH", "Конференция пройдёт в Москве", False),
    ("PLACE_OF_BIRTH", "Место проведения встречи: Казань", False),
    ("PLACE_OF_BIRTH", "Он родился в 1961 году.", False),
    ("PLACE_OF_BIRTH", "Место рождения указано в анкете.", False),
    # ── CITIZENSHIP ─────────────────────────────────────────────────────────
    ("CITIZENSHIP", "Гражданство клиента: РФ", True),
    ("CITIZENSHIP", "Клиент — гражданин Казахстана.", True),
    ("CITIZENSHIP", "Гражданство: Россия", True),
    ("CITIZENSHIP", "Клиентка — гражданка Беларуси.", True),
    ("CITIZENSHIP", "Гражданство клиента: Российская Федерация", True),
    ("CITIZENSHIP", "Для участия гражданство РФ не требуется", False),
    ("CITIZENSHIP", "Правила получения гражданства Казахстана опубликованы.", False),
    ("CITIZENSHIP", "Гражданство — это правовая связь человека с государством.", False),
    ("CITIZENSHIP", "Вопросы гражданства регулируются законом.", False),
    ("CITIZENSHIP", "Он получил гражданство в 2020 году.", False),
    # ── PASSPORT_ISSUER ─────────────────────────────────────────────────────
    ("PASSPORT_ISSUER", "Паспорт выдан ГУ МВД России по г. Москве", True),
    ("PASSPORT_ISSUER", "Кем выдан паспорт: ОМВД России по району Арбат", True),
    ("PASSPORT_ISSUER", "Паспорт выдан УФМС России по г. Санкт-Петербургу", True),
    ("PASSPORT_ISSUER", "Орган выдавший паспорт: МВД России", True),
    ("PASSPORT_ISSUER", "Паспорт выдан отделом УВД по району", True),
    ("PASSPORT_ISSUER", "ГУ МВД России по г. Москве указано в справочнике организаций", False),
    ("PASSPORT_ISSUER", "Новость опубликована ОМВД России по району Арбат.", False),
    ("PASSPORT_ISSUER", "МВД России — федеральный орган исполнительной власти.", False),
    ("PASSPORT_ISSUER", "Он работает в ГУ МВД России.", False),
    ("PASSPORT_ISSUER", "Список органов МВД России опубликован.", False),
    # ── ADDRESS ─────────────────────────────────────────────────────────────
    ("ADDRESS", "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15", True),
    ("ADDRESS", "Клиент проживает: ул. Лесная, д. 5", True),
    ("ADDRESS", "Мой адрес: Волгоградский проспект, 23", True),
    ("ADDRESS", "Проживаю по адресу: г. Казань, ул. Баумана, д. 7", True),
    ("ADDRESS", "Адрес регистрации: ул. Пушкина, д. 3, кв. 12", True),
    ("ADDRESS", "Адрес отделения Банка: Москва, ул. Тверская, д. 10", False),
    ("ADDRESS", "Адрес офиса компании: ул. Лесная, д. 5", False),
    ("ADDRESS", "Встречаемся по адресу: ул. Тверская, д. 10", False),
    ("ADDRESS", "Ресторан находится по адресу: ул. Арбат, д. 1", False),
    ("ADDRESS", "Адрес склада: ул. Промышленная, д. 8", False),
    # ── CARDHOLDER_NAME ─────────────────────────────────────────────────────
    ("CARDHOLDER_NAME", "Имя держателя карты: IVAN IVANOV", True),
    ("CARDHOLDER_NAME", "Держатель карты: Анна Петрова", True),
    ("CARDHOLDER_NAME", "Имя на карте: PETR PETROV", True),
    ("CARDHOLDER_NAME", "Cardholder name: IVAN IVANOV", True),
    ("CARDHOLDER_NAME", "Имя держателя: ANNA SMIRNOVA", True),
    ("CARDHOLDER_NAME", "Докладчик: IVAN IVANOV", False),
    ("CARDHOLDER_NAME", "Автор книги: Анна Петрова", False),
    ("CARDHOLDER_NAME", "Имя держателя акции: Иван Петров", False),
    ("CARDHOLDER_NAME", "Держатель облигации: Анна Смирнова", False),
    ("CARDHOLDER_NAME", "Имя держателя полиса: Иван Иванов", False),
    # ── BIRTH_DATE ──────────────────────────────────────────────────────────
    ("BIRTH_DATE", "Дата рождения клиента: 12.03.2001", True),
    ("BIRTH_DATE", "Клиент родился 3 мая 1998 года.", True),
    ("BIRTH_DATE", "Дата рождения: 15.06.1990", True),
    ("BIRTH_DATE", "Родился 25 декабря 1985 года.", True),
    ("BIRTH_DATE", "Дата рождения клиента: 01.01.2000", True),
    ("BIRTH_DATE", "Дата заседания: 12.03.2001", False),
    ("BIRTH_DATE", "Дата публикации: 3 мая 1998 года", False),
    ("BIRTH_DATE", "Документ подписан 15.06.2020", False),
    ("BIRTH_DATE", "Дата выдачи заказа: 5 апреля 2019 года", False),
    ("BIRTH_DATE", "Срок действия до 01.01.2025", False),
    # ── PASSPORT ────────────────────────────────────────────────────────────
    ("PASSPORT", "Паспорт клиента: серия 4510, номер 123456", True),
    ("PASSPORT", "Паспорт: 45 10 123456", True),
    ("PASSPORT", "Серия паспорта 4510 номер 123456", True),
    ("PASSPORT", "Паспорт клиента 4510 123456", True),
    ("PASSPORT", "Паспорт: серия 45 10, номер 123456", True),
    ("PASSPORT", "Номер заказа: 4510 123456", False),
    ("PASSPORT", "Артикул изделия: 4510123456", False),
    ("PASSPORT", "Номер договора: 4510 123456", False),
    ("PASSPORT", "Код операции: 4510123456", False),
    ("PASSPORT", "Номер накладной: 4510123456", False),
    # ── SUBDIVISION_CODE ────────────────────────────────────────────────────
    ("SUBDIVISION_CODE", "Код подразделения паспорта: 770-001", True),
    ("SUBDIVISION_CODE", "Паспорт: код подразделения 780-002", True),
    ("SUBDIVISION_CODE", "Код подразделения: 770-123", True),
    ("SUBDIVISION_CODE", "Код подразделения паспорта 780-456", True),
    ("SUBDIVISION_CODE", "Подразделение: 770-789", True),
    ("SUBDIVISION_CODE", "В справочнике указан код 770-001", False),
    ("SUBDIVISION_CODE", "Код товара: 780-002", False),
    ("SUBDIVISION_CODE", "Код операции: 770-001", False),
    ("SUBDIVISION_CODE", "Номер заявки: 780-002", False),
    ("SUBDIVISION_CODE", "Код клиента: 770-001", False),
    # ── PASSPORT_ISSUE_DATE ─────────────────────────────────────────────────
    ("PASSPORT_ISSUE_DATE", "Дата выдачи паспорта: 15.06.2020", True),
    ("PASSPORT_ISSUE_DATE", "Паспорт выдан 5 апреля 2019 года.", True),
    ("PASSPORT_ISSUE_DATE", "Дата выдачи: 01.01.2018", True),
    ("PASSPORT_ISSUE_DATE", "Паспорт выдан 12.03.2017", True),
    ("PASSPORT_ISSUE_DATE", "Дата выдачи паспорта 25.12.2016", True),
    ("PASSPORT_ISSUE_DATE", "Документ опубликован 15.06.2020", False),
    ("PASSPORT_ISSUE_DATE", "Дата выдачи заказа: 5 апреля 2019 года", False),
    ("PASSPORT_ISSUE_DATE", "Дата выдачи карты: 01.01.2018", False),
    ("PASSPORT_ISSUE_DATE", "Дата выдачи справки: 12.03.2017", False),
    ("PASSPORT_ISSUE_DATE", "Дата выдачи полиса: 25.12.2016", False),
    # ── DRIVER_LICENSE ──────────────────────────────────────────────────────
    ("DRIVER_LICENSE", "Водительское удостоверение: серия 77 11, номер 123456", True),
    ("DRIVER_LICENSE", "ВУ клиента: 7711123456", True),
    ("DRIVER_LICENSE", "Водительское удостоверение 77 11 123456", True),
    ("DRIVER_LICENSE", "Серия ВУ 77 11 номер 123456", True),
    ("DRIVER_LICENSE", "Права: серия 77 11, номер 123456", True),
    ("DRIVER_LICENSE", "Номер заявки: 77 11 123456", False),
    ("DRIVER_LICENSE", "Номер накладной: 7711123456", False),
    ("DRIVER_LICENSE", "Номер заказа: 77 11 123456", False),
    ("DRIVER_LICENSE", "Код операции: 7711123456", False),
    ("DRIVER_LICENSE", "Номер договора: 77 11 123456", False),
    # ── CVV ─────────────────────────────────────────────────────────────────
    ("CVV", "CVV карты: 123", True),
    ("CVV", "CVC: 456", True),
    ("CVV", "CVV2: 789", True),
    ("CVV", "Код безопасности карты: 123", True),
    ("CVV", "CVV на обороте карты: 456", True),
    ("CVV", "Код офиса: 123", False),
    ("CVV", "В очереди 456 человек.", False),
    ("CVV", "Код операции: 789", False),
    ("CVV", "Номер заказа: 123", False),
    ("CVV", "Код двери: 456", False),
    # ── PIN ─────────────────────────────────────────────────────────────────
    ("PIN", "PIN-код карты: 4821", True),
    ("PIN", "ПИН банковской карты: 9057", True),
    ("PIN", "PIN: 1234", True),
    ("PIN", "Пин-код: 5678", True),
    ("PIN", "PIN код карты: 4321", True),
    ("PIN", "Код двери: 4821", False),
    ("PIN", "PIN SIM-карты: 9057", False),
    ("PIN", "Код офиса: 1234", False),
    ("PIN", "Номер заказа: 5678", False),
    ("PIN", "Код операции: 4321", False),
    # ── EMAIL ───────────────────────────────────────────────────────────────
    ("EMAIL", "Email клиента: ivanov@example.ru", True),
    ("EMAIL", "Почта клиента: anna.petrov@example.com", True),
    ("EMAIL", "Мой email: test@example.org", True),
    ("EMAIL", "Email: ivan@mail.ru", True),
    ("EMAIL", "Почта: petrov@yandex.ru", True),
    ("EMAIL", "Почта поддержки: support@bank.ru", False),
    ("EMAIL", "Пример email: example@example.com", False),
    ("EMAIL", "Email для связи: info@company.ru", False),
    ("EMAIL", "Шаблон email: template@example.com", False),
    ("EMAIL", "Тестовый email: test@test.ru", False),
    # ── PHONE ───────────────────────────────────────────────────────────────
    ("PHONE", "Телефон клиента: +7 999 123-45-67", True),
    ("PHONE", "Телефон клиента: 8 (999) 123 45 67", True),
    ("PHONE", "Мой телефон: +7 911 222-33-44", True),
    ("PHONE", "Позвоните мне на +7 999 111-22-33", True),
    ("PHONE", "Мобильный: +7 900 000-00-00", True),
    ("PHONE", "Телефон колл-центра: +7 999 123-45-67", False),
    ("PHONE", "Номер заказа: 99912", False),
    ("PHONE", "Пример номера: +7 999 123-45-67", False),
    ("PHONE", "Код операции: 9991234567", False),
    ("PHONE", "Телефон поддержки: 8 800 123-45-67", False),
    # ── INN ─────────────────────────────────────────────────────────────────
    ("INN", "ИНН клиента: 123456789047", True),
    ("INN", "ИНН физического лица: 123456789047", True),
    ("INN", "Мой ИНН: 123456789047", True),
    ("INN", "ИНН: 123456789047", True),
    ("INN", "ИНН клиента 123456789047", True),
    ("INN", "ИНН организации: 7707083893", False),
    ("INN", "ИНН клиента: 123456789048", False),
    ("INN", "Код операции: 123456789047", False),
    ("INN", "Номер заказа: 123456789047", False),
    ("INN", "ИНН компании: 7707083893", False),
    # ── PAYMENT_CARD ────────────────────────────────────────────────────────
    ("PAYMENT_CARD", "Номер карты клиента: 4111 1111 1111 1111", True),
    ("PAYMENT_CARD", "Карта клиента: 5555-5555-5555-4444", True),
    ("PAYMENT_CARD", "Номер карты: 4111 1111 1111 1111", True),
    ("PAYMENT_CARD", "Моя карта: 5555 5555 5555 4444", True),
    ("PAYMENT_CARD", "Карта: 4111 1111 1111 1111", True),
    ("PAYMENT_CARD", "Код в логе: 4111 1111 1111 1112", False),
    ("PAYMENT_CARD", "Номер карты клиента: 4111 1111 1111 1112", False),
    ("PAYMENT_CARD", "Код операции: 4111 1111 1111 1111", False),
    ("PAYMENT_CARD", "Тестовый пример карты: 4111 1111 1111 1111", False),
    ("PAYMENT_CARD", "Номер заказа: 5555 5555 5555 4444", False),
]

assert len(CASES) == 170, f"expected 170 cases, got {len(CASES)}"


def main() -> None:
    from collections import defaultdict

    by_type: dict[str, dict] = defaultdict(lambda: {"pos": 0, "neg": 0, "pos_ok": 0, "neg_ok": 0, "errors": []})
    total_ok = 0

    for typ, text, is_pos in CASES:
        findings = detect_pii(text, enable_ner=True)
        has_type = any(f.type == typ and getattr(f, "decision", "mask") == "mask" for f in findings)
        ok = has_type if is_pos else not has_type
        bucket = by_type[typ]
        if is_pos:
            bucket["pos"] += 1
            if ok:
                bucket["pos_ok"] += 1
            else:
                bucket["errors"].append(("FN", text))
        else:
            bucket["neg"] += 1
            if ok:
                bucket["neg_ok"] += 1
            else:
                bucket["errors"].append(("FP", text))
        if ok:
            total_ok += 1

    print(f"=== STAGE-1 RECONSTRUCTED 170 CASES ===")
    print(f"Total: {total_ok}/170 = {total_ok/170*100:.1f}%")
    print(f"Errors: {170-total_ok}")
    print()
    print(f"{'Type':<20}{'Pos':>5}{'Neg':>5}{'PosOK':>7}{'NegOK':>7}{'Total':>7}")
    for typ in sorted(by_type):
        b = by_type[typ]
        t = b["pos_ok"] + b["neg_ok"]
        print(f"{typ:<20}{b['pos']:>5}{b['neg']:>5}{b['pos_ok']:>7}{b['neg_ok']:>7}{t:>7}/10")
    print()
    print("=== ERRORS ===")
    for typ in sorted(by_type):
        for kind, text in by_type[typ]["errors"]:
            print(f"  [{typ}] {kind}: {text}")


if __name__ == "__main__":
    main()