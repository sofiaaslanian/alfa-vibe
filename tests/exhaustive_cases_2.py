"""Exhaustive PII cases 2/4: ADDRESS, CARDHOLDER_NAME, BIRTH_DATE, PASSPORT_NUMBER."""

from tests.exhaustive_case_helpers import pos, neg

CASES = []

# ADDRESS — 20
T = "ADDRESS"
CASES += [
    pos("address_full_home", T, "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15", "Москва, ул. Тверская, д. 10, кв. 15"),
    pos("address_bare_full", T, "Москва, ул. Тверская, д. 10, кв. 15", "Москва, ул. Тверская, д. 10, кв. 15"),
    pos("address_my", T, "Мой адрес: г. Москва, ул. Арбат, д. 7", "г. Москва, ул. Арбат, д. 7"),
    pos("address_registered", T, "Я зарегистрирован по адресу: Санкт-Петербург, Невский проспект, д. 28.", "Санкт-Петербург, Невский проспект, д. 28"),
    pos("address_delivery", T, "Адрес доставки клиента: Казань, ул. Баумана, д. 5, кв. 9", "Казань, ул. Баумана, д. 5, кв. 9"),
    pos("address_postal", T, "Адрес для корреспонденции: 190000, Санкт-Петербург, ул. Почтамтская, д. 3", "190000, Санкт-Петербург, ул. Почтамтская, д. 3"),
    pos("address_building", T, "Адрес: Москва, Ленинградский пр-т, д. 36, корп. 2, стр. 1", "Москва, Ленинградский пр-т, д. 36, корп. 2, стр. 1"),
    pos("address_linebreak", T, "Адрес проживания:\nМосква,\nул. Арбат,\nд. 10,\nкв. 2", "Москва,\nул. Арбат,\nд. 10,\nкв. 2"),
    pos("address_json", T, '{"address":"Москва, ул. Тверская, д. 1, кв. 5"}', "Москва, ул. Тверская, д. 1, кв. 5"),
    pos("address_yaml", T, "address: Екатеринбург, ул. Малышева, д. 15", "Екатеринбург, ул. Малышева, д. 15"),
    pos("address_street_house", T, "Клиент проживает: ул. Лесная, д. 5", "ул. Лесная, д. 5"),
    pos("address_prospekt", T, "Адрес регистрации: проспект Мира, дом 101, квартира 20", "проспект Мира, дом 101, квартира 20"),
    pos("address_lane", T, "Домашний адрес: пер. Сивцев Вражек, д. 12", "пер. Сивцев Вражек, д. 12"),
    pos("address_highway", T, "Адрес клиента: Варшавское шоссе, д. 9, корп. 1", "Варшавское шоссе, д. 9, корп. 1"),
    neg("address_bank_branch", T, "Адрес отделения Банка: Москва, ул. Тверская, д. 10."),
    neg("address_company_office", T, "Адрес офиса компании: ул. Лесная, д. 5."),
    neg("address_museum", T, "Музей находится по адресу: Москва, ул. Волхонка, д. 12."),
    neg("address_restaurant", T, "Ресторан расположен по адресу: Москва, ул. Арбат, д. 20."),
    neg("address_meeting", T, "Место встречи: Москва, ул. Тверская, д. 7."),
    neg("address_hq", T, "Штаб-квартира компании: Москва, ул. Ленина, д. 1."),
]

# CARDHOLDER_NAME — 20
T = "CARDHOLDER_NAME"
CASES += [
    pos("cardholder_en", T, "CARDHOLDER: IVAN PETROV", "IVAN PETROV"),
    pos("cardholder_middle_initial", T, "CARDHOLDER: IVAN I PETROV", "IVAN I PETROV"),
    pos("cardholder_name_label", T, "Cardholder name: MARIA KUZNETSOVA", "MARIA KUZNETSOVA"),
    pos("cardholder_name_on_card", T, "Name on card: JOHN SMITH", "JOHN SMITH"),
    pos("cardholder_embossed", T, "Embossed name: ANNA S IVANOVA", "ANNA S IVANOVA"),
    pos("cardholder_ru", T, "Имя держателя карты: Иван Петров", "Иван Петров"),
    pos("cardholder_holder_card", T, "Держатель карты Петров Иван", "Петров Иван"),
    pos("cardholder_name_on_ru", T, "Имя на карте: IVAN PETROV", "IVAN PETROV"),
    pos("cardholder_json", T, '{"cardholder":"IVAN PETROV"}', "IVAN PETROV"),
    pos("cardholder_yaml", T, "cardholder_name: MARIA K IVANOVA", "MARIA K IVANOVA"),
    pos("cardholder_linebreak", T, "Имя держателя карты\nIVAN PETROV", "IVAN PETROV"),
    pos("cardholder_hyphen", T, "Cardholder: ANNA PETROVA-VODKINA", "ANNA PETROVA-VODKINA"),
    neg("cardholder_company", T, "CARDHOLDER COMPANY: ACME BANK"),
    neg("cardholder_speaker", T, "Докладчик: IVAN PETROV"),
    neg("cardholder_bare_name", T, "IVAN PETROV"),
    neg("cardholder_policy_holder", T, "Держатель полиса: Иван Петров"),
    neg("cardholder_bond_holder", T, "Держатель облигации: Иван Петров"),
    neg("cardholder_shareholder", T, "Держатель акций: Иван Петров"),
    neg("cardholder_certificate", T, "Держатель сертификата: Иван Петров"),
    neg("cardholder_account", T, "Владелец счёта: Иван Петров"),
]

# BIRTH_DATE — 20
T = "BIRTH_DATE"
CASES += [
    pos("birth_dmy_dot", T, "Дата рождения: 01.02.1990", "01.02.1990"),
    pos("birth_dmy_dash", T, "Дата рождения: 01-02-1990", "01-02-1990"),
    pos("birth_dmy_slash", T, "Дата рождения: 01/02/1990", "01/02/1990"),
    pos("birth_iso_dash", T, "Дата рождения: 1990-02-01", "1990-02-01"),
    pos("birth_iso_dot", T, "Дата рождения: 1990.02.01", "1990.02.01"),
    pos("birth_iso_slash", T, "Дата рождения: 1990/02/01", "1990/02/01"),
    pos("birth_text_male", T, "Клиент родился 3 мая 1998 года.", "3 мая 1998 года"),
    pos("birth_text_female", T, "Клиентка родилась 15 декабря 1985 г.", "15 декабря 1985 г"),
    pos("birth_dr_short", T, "ДР клиента: 12.05.1988", "12.05.1988"),
    pos("birth_yaml", T, "birth_date: 1995-07-20", "1995-07-20"),
    pos("birth_linebreak", T, "Дата рождения\n04.11.2001", "04.11.2001"),
    pos("birth_leap", T, "В анкете указана дата рождения 29.02.2000.", "29.02.2000"),
    neg("birth_publication", T, "Дата публикации: 03.05.1998"),
    neg("birth_meeting", T, "Дата встречи: 12.05.1988"),
    neg("birth_contract", T, "Дата договора: 01.02.1990"),
    neg("birth_holiday", T, "Новый год отмечаем 01.01.2025"),
    neg("birth_victory_day", T, "Праздник 9 мая 09.05.2025"),
    neg("birth_issue_date", T, "Дата выдачи паспорта: 03.04.2015"),
    neg("birth_expiry", T, "Срок действия до 03.04.2035"),
    neg("birth_report", T, "Дата отчёта: 31.12.2024"),
]

# PASSPORT_NUMBER — 20
T = "PASSPORT_NUMBER"
CASES += [
    pos("passport_basic", T, "Паспорт: 4510 123456", "4510 123456"),
    pos("passport_spaced_series", T, "Паспорт 45 10 123456", "45 10 123456"),
    pos("passport_compact", T, "Паспорт 4510123456", "4510123456"),
    pos("passport_label_series_number", T, "Паспорт клиента: серия 4510, номер 123456", "4510", "123456"),
    pos("passport_series_space", T, "Паспорт серия 45 10 номер 123456", "45 10", "123456"),
    pos("passport_number_sign", T, "Паспорт: серия 4510 № 123456", "4510", "123456"),
    pos("passport_linebreak", T, "Паспорт:\n4510 123456", "4510 123456"),
    pos("passport_json", T, '{"passport":"4510 123456"}', "4510 123456"),
    pos("passport_yaml", T, "passport: 4510 123456", "4510 123456"),
    pos("passport_in_sentence", T, "Данные паспорта клиента 4510 123456 подтверждены.", "4510 123456"),
    pos("passport_semicolon", T, "Документ: паспорт; 4510 123456", "4510 123456"),
    pos("passport_ru_words", T, "серия паспорта 4510 номер 123456", "4510", "123456"),
    neg("passport_order", T, "Номер заказа: 4510 123456"),
    neg("passport_operation", T, "Код операции: 4510 123456"),
    neg("passport_contract", T, "Номер договора: 4510 123456"),
    neg("passport_example", T, "Пример паспорта: 40 00 000000"),
    neg("passport_equipment", T, "Серийный номер оборудования: 4510 123456"),
    neg("passport_tracking", T, "Tracking: 4510 123456"),
    neg("passport_bare", T, "4510 123456"),
    neg("passport_driver_context", T, "ВУ серия 45 10 номер 123456"),
]

assert len(CASES) == 80
