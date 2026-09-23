"""Exhaustive PII cases 4/4: PIN, EMAIL, PHONE, INN, PAYMENT_CARD."""

from tests.exhaustive_case_helpers import pos, neg

CASES = []

# CARD_PIN — 20
T = "CARD_PIN"
CASES += [
    pos("pin_basic", T, "PIN-код карты: 4321", "4321"),
    pos("pin_short_label", T, "PIN: 9057", "9057"),
    pos("pin_ru", T, "Пин карты: 2468", "2468"),
    pos("pin_card_near", T, "Карта 4111111111111111, PIN 1357", "1357"),
    pos("pin_json", T, '{"card_pin":"9988"}', "9988"),
    pos("pin_yaml", T, "pin: 1122", "1122"),
    pos("pin_linebreak", T, "PIN-код карты\n3344", "3344"),
    pos("pin_six", T, "PIN карты: 123456", "123456"),
    pos("pin_sentence", T, "Клиент сообщил PIN-код карты 7788.", "7788"),
    pos("pin_caps", T, "CARD PIN: 4455", "4455"),
    pos("pin_quotes", T, 'PIN-код: «6677»', "6677"),
    pos("pin_payment_json", T, 'payment={"pin":"8899"}', "8899"),
    neg("pin_sim", T, "PIN SIM-карты: 9057"),
    neg("pin_otp", T, "Одноразовый код: 4321"),
    neg("pin_sms", T, "Код из СМС: 2468"),
    neg("pin_door", T, "PIN домофона: 1357"),
    neg("pin_bare", T, "4321"),
    neg("pin_order", T, "Код заказа: 9988"),
    neg("pin_office", T, "Код офиса: 1122"),
    neg("pin_cvv", T, "CVV карты: 123"),
]

# EMAIL — 20
T = "EMAIL"
CASES += [
    pos("email_basic", T, "Email клиента: ivan@example.ru", "ivan@example.ru"),
    pos("email_bare", T, "ivan.petrov@gmail.com", "ivan.petrov@gmail.com"),
    pos("email_plus", T, "Почта клиента: ivan.petrov+vip@example.com", "ivan.petrov+vip@example.com"),
    pos("email_upper", T, "Email: IVAN.PETROV@EXAMPLE.RU", "IVAN.PETROV@EXAMPLE.RU"),
    pos("email_subdomain", T, "Email: a.b@payments.example.ru", "a.b@payments.example.ru"),
    pos("email_mailto", T, "mailto:anna.k@bank-client.ru", "anna.k@bank-client.ru"),
    pos("email_angle", T, "Контакт <client@alfa-demo.ru>", "client@alfa-demo.ru"),
    pos("email_json", T, '{"email":"ivan@example.ru"}', "ivan@example.ru"),
    pos("email_yaml", T, "email: ivan@example.ru", "ivan@example.ru"),
    pos("email_url_query", T, "https://site.ru/reset?email=ivan@example.ru&step=2", "ivan@example.ru"),
    pos("email_two_personal", T, "Основная почта a@x.ru, резервная b@y.ru", "a@x.ru", "b@y.ru"),
    pos("email_client_vs_support", T, "Почта клиента a@x.ru; поддержка support@bank.ru", "a@x.ru", must_not=("support@bank.ru",)),
    neg("email_support", T, "Почта поддержки: support@bank.ru"),
    neg("email_noreply", T, "Системный отправитель noreply@example.ru"),
    neg("email_template", T, "Пример email: test@example.com"),
    neg("email_invalid_double_dot", T, "Email: ivan..petrov@example.ru"),
    neg("email_invalid_domain", T, "Email: ivan@bad_domain.ru"),
    neg("email_no_tld", T, "Email: ivan@example"),
    neg("email_cyrillic_local", T, "Email: ivаn@example.ru"),
    neg("email_merchant", T, "merchant email: shop@example.ru"),
]

# PHONE — 20
T = "PHONE"
CASES += [
    pos("phone_plus7", T, "Телефон клиента: +7 999 123-45-67", "+7 999 123-45-67"),
    pos("phone_eight", T, "Мой номер 8 (916) 555-44-33", "8 (916) 555-44-33"),
    pos("phone_compact", T, "Телефон: +79991234567", "+79991234567"),
    pos("phone_dashes", T, "Телефон клиента +7-999-111-22-33", "+7-999-111-22-33"),
    pos("phone_dots", T, "Мобильный +7.999.111.22.33", "+7.999.111.22.33"),
    pos("phone_tel_uri", T, "tel:+79991234567", "+79991234567"),
    pos("phone_extension", T, "Телефон клиента +7 495 123-45-67 доб. 1234", "+7 495 123-45-67"),
    pos("phone_json", T, '{"phone":"+79991234567"}', "+79991234567"),
    pos("phone_yaml", T, "phone: +79991234567", "+79991234567"),
    pos("phone_linebreak", T, "Телефон клиента\n+7 999 123-45-67", "+7 999 123-45-67"),
    pos("phone_two", T, "Телефоны клиента +79991234567 и +79161234567", "+79991234567", "+79161234567"),
    pos("phone_personal_override", T, "Личный телефон поддержки: +7 999 000-11-22", "+7 999 000-11-22"),
    neg("phone_hotline", T, "Горячая линия: 8 800 200-00-00"),
    neg("phone_support", T, "Телефон поддержки Альфа-Банка: +7 495 788-88-78"),
    neg("phone_office", T, "Телефон офиса: +7 495 000-00-00"),
    neg("phone_order", T, "Номер заказа: 89991234567"),
    neg("phone_card", T, "PAN 4111111111111111"),
    neg("phone_bare_short", T, "1234567"),
    neg("phone_tracking", T, "Tracking 89991234567"),
    neg("phone_code", T, "Код операции 89991234567"),
]

# INN — 20
T = "INN"
INN1 = "500100732259"
INN2 = "415345080525"
CASES += [
    pos("inn_basic", T, f"ИНН клиента: {INN1}", INN1),
    pos("inn_bare_valid", T, INN1, INN1),
    pos("inn_yaml", T, f"inn: {INN1}", INN1),
    pos("inn_json", T, f'{{"inn":"{INN1}"}}', INN1),
    pos("inn_linebreak", T, f"ИНН клиента\n{INN1}", INN1),
    pos("inn_sentence", T, f"У клиента ИНН {INN1}.", INN1),
    pos("inn_two", T, f"ИНН клиента {INN1}, второй ИНН {INN2}", INN1, INN2),
    pos("inn_self", T, f"Мой ИНН {INN1}", INN1),
    pos("inn_caps", T, f"INN: {INN1}", INN1),
    pos("inn_brackets", T, f"ИНН ({INN1})", INN1),
    pos("inn_semicolon", T, f"Клиент; ИНН={INN1}", INN1),
    pos("inn_text", T, f"Проверьте ИНН клиента {INN1}", INN1),
    neg("inn_org10", T, "ИНН организации 7707083893"),
    neg("inn_invalid_checksum", T, "ИНН клиента 500100732258"),
    neg("inn_operation", T, f"ID операции {INN1}"),
    neg("inn_contract", T, f"Номер договора {INN1}"),
    neg("inn_order", T, f"Номер заказа {INN1}"),
    neg("inn_tracking", T, f"Tracking {INN1}"),
    neg("inn_spaced", T, "ИНН 5001 0073 2259"),
    neg("inn_batch", T, f"Код партии {INN1}"),
]

# PAYMENT_CARD — 20
T = "PAYMENT_CARD"
CARD1 = "4111 1111 1111 1111"
CARD2 = "5555 5555 5555 4444"
CASES += [
    pos("card_basic", T, f"Карта {CARD1}", CARD1),
    pos("card_bare_valid", T, "4111111111111111", "4111111111111111"),
    pos("card_dashes", T, "Карта 4111-1111-1111-1111", "4111-1111-1111-1111"),
    pos("card_nbsp", T, "Карта 4111\u00a01111\u00a01111\u00a01111", "4111\u00a01111\u00a01111\u00a01111"),
    pos("card_json", T, '{"card":"4111111111111111"}', "4111111111111111"),
    pos("card_yaml", T, "card: 4111111111111111", "4111111111111111"),
    pos("card_pan", T, "PAN клиента: 4111111111111111", "4111111111111111"),
    pos("card_number", T, f"Номер карты: {CARD1}", CARD1),
    pos("card_two", T, f"Карты клиента: {CARD1} и {CARD2}", CARD1, CARD2),
    pos("card_parentheses", T, f"Оплата ({CARD1}) подтверждена.", CARD1),
    pos("card_in_sentence", T, f"Списание с карты {CARD1} прошло.", CARD1),
    pos("card_keyword_invalid_luhn", T, "Карта 4111 1111 1111 1112", "4111 1111 1111 1112"),
    neg("card_order", T, "Номер заказа 4111111111111111"),
    neg("card_operation", T, "Код операции 4111111111111111"),
    neg("card_contract", T, "Номер договора 4111111111111111"),
    neg("card_serial", T, "Серийный номер 4111111111111111"),
    neg("card_example", T, "Тестовый пример карты 4111111111111111"),
    neg("card_invalid_bare", T, "4111111111111112"),
    neg("card_tracking", T, "Tracking 4111111111111111"),
    neg("card_batch", T, "Код партии 4111111111111111"),
]

assert len(CASES) == 100
