# AlfaGen — модуль защиты ПД

Прокси: **detect → mask → (LLM) → demask**. Маска автотеста: `dev_redact_v1` (буквы/цифры → `*`).

## Быстрый старт

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --port 8080 --reload
```

```bash
# mask
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент ivanov@mail.ru","payload_id":"t1"}'

# demask (тот же payload_id + masked строка)
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -d '{"payload":"<masked>","payload_id":"t1"}'
```

## Redis (shared state / несколько workers)

```bash
docker compose up -d redis
export STORAGE_BACKEND=redis REDIS_URL=redis://localhost:6379/0
uvicorn app.main:app --port 8080 --workers 2
```

Или всё вместе: `docker compose up --build`.

Контракт state: retry той же строки → та же маска; demask; чужой payload на том же id → **409**; истёкший seen → **410**.

## Demo proxy → AlfaGen

Заголовок `X-API-Key` (см. `PROXY_API_KEYS`), система `X-System` из `config.yaml`.

```bash
curl -s localhost:8080/proxy/chat \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: demo-key' \
  -H 'X-System: demo' \
  -H 'X-Consumer-Id: demo' \
  -d '{"text":"Напиши письмо клиенту Ивану Петрову на ivan@mail.ru"}'
```

В LLM уходит только masked prompt (scoped tokens). Demask ответа — только если `allow_demask: true` у системы.

| Система | Типы | demask | Назначение |
|---|---|---|---|
| `autotest` | все | да | `/process` |
| `demo` | все | да | proxy демо |
| `format_only` | email/phone/INN/card | нет | урезанный consumer |

## Метрики и нагрузка

- Prometheus: `GET /metrics` (Latency / RPS / TPS)
- Ready: `GET /ready` (проверка state store)
- Локальный smoke: `python scripts/load_smoke.py --n 200 --concurrency 20`
- На RU-сервере: тот же скрипт с `--url https://<your-host>` после деплоя

## Документы

| Файл | Зачем |
|---|---|
| [`docs/START_HERE.md`](docs/START_HERE.md) | baseline v1 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | API / Redis / маски |
| [`docs/DETECTION.md`](docs/DETECTION.md) | 17 типов |
| [`docs/acceptance_cases.json`](docs/acceptance_cases.json) | 68 кейсов |
| [`docs/HACKATHON_BRIEF.md`](docs/HACKATHON_BRIEF.md) | критерии жюри |

## Структура

```text
app/
  api.py process.py state.py masking.py crypto_util.py
  config.py llm.py
  pii/detect.py rules.py ner.py
docs/ tests/ scripts/
```

## Тесты

```bash
pytest -q
```

ФИО (RuBERT): `NER_ENABLED=1 NER_LOCAL=1` (первый запуск качает модель).
