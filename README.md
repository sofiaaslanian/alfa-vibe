# Alfa Vibe — модуль безопасности ПД

Документы архитектуры:
- [`docs/PII_DETECTION_ARCHITECTURE.md`](docs/PII_DETECTION_ARCHITECTURE.md)
- [`docs/final_architecture_artifact_v2.md`](docs/final_architecture_artifact_v2.md)

## Быстрый старт

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # при необходимости ключ AlfaGen
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

```bash
curl -s localhost:8080/health
curl -s -X POST localhost:8080/process \
  -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент ivan@mail.ru, тел +7 999 123-45-67","payload_id":"t1"}'
```

## Detection v1

| Группа | Реализация |
|---|---|
| Format | `app/pii/rules/` — email, phone, INN(+checksum), card(+Luhn) |
| Format-context | address, dates, passport, VU, subdivision, CVV, PIN |
| Context (ФИО) | NER service на `redmadrobot-rnd/rubert-base-pii-ner` (opt-in) |

Включить NER:

```bash
# отдельный сервис (рекомендуется)
pip install transformers torch
NER_PRELOAD=1 uvicorn services.ner.app:app --port 8090
# в proxy:
NER_ENABLED=1 NER_URL=http://127.0.0.1:8090
```

Или локально в том же процессе: `NER_ENABLED=1 NER_LOCAL=1`.

## Тесты

```bash
pytest -q
```

## Контур AlfaGen / Kilo

LLM-клиент: `app/core/llm.py` → `ALFAGEN_BASE_URL` / `ALFAGEN_API_KEY` / `ALFAGEN_MODEL=deepseek-v.4-flash`.
