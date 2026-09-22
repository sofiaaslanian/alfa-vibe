# PII Detection

Внутренний detection layer. Не меняет `/process`, state, masking API.

См. также: `final_architecture_artifact_v2.md` (прокси, state, маски).

---

## 1. Выбор подходов

| Группа | Типы | Подход |
|---|---|---|
| Format | Email, phone, ИНН, карта | **Rules** в репо |
| Context | ФИО (+ роль: место рождения, гражданство, орган, держатель карты) | **ML:** `redmadrobot-rnd/rubert-base-pii-ner` |
| Format-context | Адрес, даты, паспорт/ВУ, код подразделения, CVV, PIN | **Rules**; LLM fallback опционально |

Адрес = format-context (rules), не NER.

**Policy задаёт наш код, не модель.** ML только предлагает spans.

```text
format → rules → format-context rules → [NER если нужны context-типы]
→ allowlist/mapper → eligibility → resolver → masker → LLM
```

HF — только скачать веса. Инференс локальный. DeepSeek/Kilo — разработка, не runtime NER.

Benchmark авторов модели: ML 83.6% F1 → rules+ML **88.9%**.

---

## 2. Contract

```json
{"type":"EMAIL","start":31,"end":48,"score":0.99,"detector":"email_rule_v1"}
```

NER: `POST /detect` `{"text":"..."}` → `{"entities":[...]}`.

Score между Rule/ML не сравниваем. Threshold — per type.

---

## 3. ML (RuBERT)

- Модель: [`redmadrobot-rnd/rubert-base-pii-ner`](https://huggingface.co/redmadrobot-rnd/rubert-base-pii-ner) (~0.2B, 21 label)
- Отдельный container (не в каждой реплике proxy)
- Chunking: `max_length=512`, `stride=128` → global offsets → merge
- MVP allowlist: `FIRST_NAME|LAST_NAME|MIDDLE_NAME` → merge `PERSON`
- Прочие labels модели (EMAIL, PHONE, INN, CARD…) **игнор** — их закрывают rules
- Role-типы позже: context adapter или fine-tune; API `/detect` не меняется
- Fail closed, если NER нужен и недоступен

```python
LABEL_MAP = {"FIRST_NAME":"PERSON","LAST_NAME":"PERSON","MIDDLE_NAME":"PERSON"}
```

---

## 4. Rules — что реализовать

**Format:** `candidate → validate → exact span`

| Тип | Validate | Hard negative |
|---|---|---|
| Email | syntax | service domains (`support@…`) |
| Phone | RU length/`+7` | колл-центр |
| INN | 12 dig + checksum | число без checksum |
| Card | Luhn | non-Luhn ID |

**Format-context:** `candidate → hotword± (proximity) → span`

| Тип | Candidate | Context+ | Context− |
|---|---|---|---|
| Address | grammar ул/д/кв | компоненты | отделение банка |
| Birth date | date parser | родился / дата рождения | заседание |
| Passport | series+number | паспорт | номер заказа |
| Subdivision | `NNN-NNN` | код подразделения | голый XXX-XXX |
| Issue date | date | выдан | опубликован |
| VU | series+number | ВУ / права | заявка |
| CVV | 3–4 dig | CVV/CVC | код офиса |
| PIN | 4–6 dig | PIN | код двери |

Patterns компилировать при старте; исходник не мутировать; version id у rule.

---

## 5. Структура

```text
app/pii/
  rules/     email phone inn card address dates passport … 
  ner/       model mapper chunking client
  resolver.py eligibility.py masker.py pipeline.py
services/ner/   FastAPI POST /detect + RuBERT
```

Pipeline:

```python
rules = detect_all_rules(text)
ml = [map_entity(e) for e in ner.predict(text) if map_entity(e)]
return resolve_overlaps(filter_findings(rules + ml))
```

---

## 6. Тесты / DoD

На тип: + / variant+ / hard− / offsets / round-trip / no PII in logs.

- [ ] 17 типов нужным классом  
- [ ] Rules в repo + fixtures  
- [ ] NER = RuBERT local, allowlist, PERSON merge, chunking  
- [ ] LLM не hot path; ADDRESS = rules  
- [ ] Fine-tune без смены API  
