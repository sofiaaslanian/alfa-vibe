"""Exhaustive PII cases 1/4: PERSON, PLACE_OF_BIRTH, CITIZENSHIP, PASSPORT_ISSUER."""

from tests.exhaustive_case_helpers import pos, neg

CASES = []

# PERSON_NAME — 20
T = "PERSON_NAME"
CASES += [
    pos("person_bare_first_last", T, "Иван Иванов", "Иван Иванов"),
    pos("person_bare_last_first", T, "Иванов Иван", "Иванов Иван"),
    pos("person_bare_full_patronymic", T, "Петров Иван Сергеевич", "Петров Иван Сергеевич"),
    pos("person_self_named", T, "Меня зовут София Асланян.", "София Асланян"),
    pos("person_self_dash", T, "Я — Мария Кузнецова.", "Мария Кузнецова"),
    pos("person_label_lowercase", T, "ФИО клиента: иван петров", "иван петров"),
    pos("person_client_inflected", T, "Клиенту Ивану Петрову нужно перевыпустить карту.", "Ивану Петрову"),
    pos("person_contact_inflected", T, "Свяжитесь с Анной Сергеевой.", "Анной Сергеевой"),
    pos("person_hyphen_surname", T, "Клиент Анна Петрова-Водкина подтвердила данные.", "Анна Петрова-Водкина"),
    pos("person_yo_name", T, "Клиент Алёна Фёдорова подала заявку.", "Алёна Фёдорова"),
    pos("person_json_customer", T, '{"customer":{"name":"Дмитрий Орлов"}}', "Дмитрий Орлов"),
    pos("person_yaml_fio", T, "fio: Петров Иван\nstatus: active", "Петров Иван"),
    pos("person_latin_customer", T, "Customer name: John Smith", "John Smith"),
    pos("person_two_clients", T, "Клиенты Иван Петров и Анна Смирнова подтвердили данные.", "Иван Петров", "Анна Смирнова"),
    pos("person_quotes", T, 'Клиент — «Иван Петров» — подтвердил заявку.', "Иван Петров"),
    neg("person_poet_public", T, "Поэт Александр Пушкин — классик русской литературы."),
    neg("person_speaker_public", T, "Докладчик Иван Петров выступил на конференции."),
    neg("person_company_title", T, 'Компания ООО «Иван Петров» заключила договор.'),
    neg("person_author_public", T, "Писатель Лев Толстой написал роман «Война и мир»."),
    pos(
        "person_manager_vs_client",
        T,
        "Менеджер Анна Смирнова оформила заявку. Клиент Иван Петров подтвердил данные.",
        "Иван Петров",
        must_not=("Анна Смирнова",),
    ),
]

# PLACE_OF_BIRTH — 20
T = "PLACE_OF_BIRTH"
CASES += [
    pos("pob_label_city", T, "Место рождения: Москва", "Москва"),
    pos("pob_born_male", T, "Клиент родился в Казани.", "Казани"),
    pos("pob_born_female", T, "Клиентка родилась в Самаре.", "Самаре"),
    pos("pob_client_dash", T, "Место рождения клиента — г. Омск", "г. Омск"),
    pos("pob_yaml", T, "place_of_birth: Новосибирск", "Новосибирск"),
    pos("pob_json", T, '{"place_of_birth":"Пермь"}', "Пермь"),
    pos("pob_lowercase", T, "место рождения: москва", "москва"),
    pos("pob_eng_label_ru_value", T, "Place of birth: Санкт-Петербург", "Санкт-Петербург"),
    pos("pob_region", T, "Место рождения: Московская область", "Московская область"),
    pos("pob_country", T, "Место рождения клиента: Республика Беларусь", "Республика Беларусь"),
    pos("pob_linebreak", T, "Место рождения\nЕкатеринбург", "Екатеринбург"),
    pos("pob_in_sentence", T, "В анкете указано место рождения — Тула.", "Тула"),
    neg("pob_conference", T, "Конференция пройдёт в Москве."),
    neg("pob_meeting", T, "Место проведения встречи: Казань."),
    neg("pob_bare_city", T, "Москва"),
    neg("pob_biography", T, "Александр Пушкин родился в Москве."),
    neg("pob_trip", T, "Завтра летим в Казань."),
    neg("pob_branch_city", T, "Отделение банка находится в Самаре."),
    neg("pob_weather", T, "Сегодня в Омске ожидается дождь."),
    neg("pob_event_history", T, "Олимпиада проходила в Сочи."),
]

# CITIZENSHIP — 20
T = "CITIZENSHIP"
CASES += [
    pos("citizenship_label_rf", T, "Гражданство клиента: РФ", "РФ"),
    pos("citizenship_citizen_kz", T, "Клиент — гражданин Казахстана.", "Казахстана"),
    pos("citizenship_female_armenia", T, "Клиентка является гражданкой Армении.", "Армении"),
    pos("citizenship_russia", T, "гражданство: Россия", "Россия"),
    pos("citizenship_full_name", T, "Гражданство клиента — Российская Федерация.", "Российская Федерация"),
    pos("citizenship_belarus", T, "Гражданство заявителя: Республика Беларусь", "Республика Беларусь"),
    pos("citizenship_yaml", T, "citizenship: Казахстан", "Казахстан"),
    pos("citizenship_json", T, '{"citizenship":"Россия"}', "Россия"),
    pos("citizenship_linebreak", T, "Гражданство клиента\nУзбекистан", "Узбекистан"),
    pos("citizenship_in_sentence", T, "В анкете клиента указано гражданство Киргизия.", "Киргизия"),
    pos("citizenship_abbrev", T, "Гражданство: РБ", "РБ"),
    pos("citizenship_eng_label", T, "Citizenship: Russian Federation", "Russian Federation"),
    neg("citizenship_requirements", T, "Для участия гражданство РФ не требуется."),
    neg("citizenship_rules", T, "Правила получения гражданства Казахстана опубликованы."),
    neg("citizenship_article", T, "Статья рассказывает о гражданстве Армении."),
    neg("citizenship_bare_country", T, "Россия"),
    neg("citizenship_law", T, "Закон о гражданстве Российской Федерации вступил в силу."),
    neg("citizenship_statistics", T, "Статистика по гражданству жителей обновлена."),
    neg("citizenship_news", T, "Новость о двойном гражданстве опубликована утром."),
    neg("citizenship_form_instruction", T, "В поле «гражданство» укажите страну."),
]

# PASSPORT_ISSUER — 20
T = "PASSPORT_ISSUER"
CASES += [
    pos("issuer_passport_issued", T, "Паспорт выдан ГУ МВД России по г. Москве.", "ГУ МВД России по г. Москве"),
    pos("issuer_kem_vidan", T, "Кем выдан паспорт: ОМВД России по району Арбат", "ОМВД России по району Арбат"),
    pos("issuer_ufms", T, "Паспорт выдан УФМС России по Московской области.", "УФМС России по Московской области"),
    pos("issuer_mvd", T, "Орган, выдавший паспорт: МВД России по Республике Татарстан", "МВД России по Республике Татарстан"),
    pos("issuer_organ_vydachi", T, "Орган выдачи паспорта — ОМВД России по району Хамовники.", "ОМВД России по району Хамовники"),
    pos("issuer_organ_vydavshiy", T, "Орган, выдавший паспорт — ГУ МВД России по г. Санкт-Петербургу.", "ГУ МВД России по г. Санкт-Петербургу"),
    pos("issuer_yaml", T, "passport_issuer: ОМВД России по району Тверской", "ОМВД России по району Тверской"),
    pos("issuer_json", T, '{"passport_issuer":"ГУ МВД России по г. Москве"}', "ГУ МВД России по г. Москве"),
    pos("issuer_linebreak", T, "Паспорт выдан\nОМВД России по району Арбат", "ОМВД России по району Арбат"),
    pos("issuer_semicolon", T, "Паспорт: 4510 123456; выдан ОМВД России по району Арбат.", "ОМВД России по району Арбат"),
    pos("issuer_district_long", T, "Кем выдан паспорт: Отделом МВД России по району Замоскворечье г. Москвы", "Отделом МВД России по району Замоскворечье г. Москвы"),
    pos("issuer_eng_label", T, "Passport issued by: Moscow Department of Internal Affairs", "Moscow Department of Internal Affairs"),
    neg("issuer_reference", T, "ГУ МВД России по г. Москве указано в справочнике организаций."),
    neg("issuer_news", T, "Новость опубликована ОМВД России по району Арбат."),
    neg("issuer_contact", T, "Свяжитесь с ГУ МВД России по г. Москве."),
    neg("issuer_office", T, "Офис ГУ МВД России по г. Москве работает до 18:00."),
    neg("issuer_bare_org", T, "ОМВД России по району Арбат"),
    neg("issuer_history", T, "История УФМС России опубликована на сайте."),
    neg("issuer_address", T, "Адрес ГУ МВД России по г. Москве: ул. Петровка, д. 38."),
    neg("issuer_instruction", T, "В поле «кем выдан» укажите название органа."),
]

assert len(CASES) == 80
