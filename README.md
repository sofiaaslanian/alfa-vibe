# AlfaGen — модуль защиты ПД

Прокси: **detect → mask → (LLM) → demask**. Маска автотеста: `dev_redact_v1` (буквы/цифры → `*`).

## Demo UI

После старта сервиса:
- Контур (скринкаст): http://localhost:8080/
- Доказательства: http://localhost:8080/evidence

`X-API-Key` по умолчанию `demo-key` (см. `.env`). Чекбокс «Без LLM» — безопасный прогон без AlfaGen.

## Быстрый старт

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # API + load (без torch)
# pip install -r requirements-ner.txt    # опционально RuBERT FIO
cp .env.example .env                     # прописать ключи / STATE_*
uvicorn app.main:app --port 8080 --reload
```

Docker-образ **без** torch (лёгкий). NER на RU только если отдельно поставите `requirements-ner.txt` и `NER_ENABLED=1`.

```bash
# mask
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -H 'X-API-Key: demo-key' \
  -d '{"payload":"Клиент ivanov@mail.ru","payload_id":"t1"}'

# demask (тот же payload_id + masked строка)
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -H 'X-API-Key: demo-key' \
  -d '{"payload":"<masked>","payload_id":"t1"}'
```

## Redis (shared state / несколько workers)

```bash
docker compose up -d redis
export STORAGE_BACKEND=redis REDIS_URL=redis://localhost:6379/0
uvicorn app.main:app --port 8080 --workers 2
```

Или всё вместе: `docker compose up --build`.

Redis в Compose **не** публикует `6379` наружу (только сеть `redis:6379` между сервисами).

Контракт state: retry той же строки → та же маска; demask; чужой payload на том же id → **409**; истёкший seen → **410**.

### Перед деплоем / сдачей ZIP

1. Сгенерировать **новые** `STATE_HMAC_KEY` / `STATE_ENC_KEY` на сервере (ключи из любого переданного ZIP считать скомпрометированными).
2. В архив — только исходники: `./scripts/pack_submission.sh` (`.env` не кладётся).
3. Acceptance: `68/68` — внутренний набор; на слайде не писать «Precision 100% на данных Альфы».

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

| Система | Типы | demask | NER | Назначение |
|---|---|---|---|---|
| `autotest` | все | да | нет | `/process` нагрузка |
| `demo` | все + combo PIN/CVV↔карта | да | **RuBERT** | proxy / UI / ловушки |
| `format_only` | email/phone/INN/card | нет | нет | урезанный consumer |
| `high_rps` | все 17 типов | да | нет | нагрузка без ML |

**Контекстные ПД:** в `demo` RuBERT (`redmadrobot-rnd/rubert-base-pii-ner`) добавляет кандидатов в свободном тексте, точные labelled/role rules работают параллельно; **discourse** решает «клиент / меня зовут» vs «поэт Пушкин». Natasha не используется.  
Включить локально: `pip install -r requirements-ner.txt` и `NER_ENABLED=1` в `.env`.  
Бонус УЛ: `SNILS`, `INTERNATIONAL_PASSPORT`, `OMS`.  
Combo на `demo`: PIN/CVV маскируются только вместе с `PAYMENT_CARD`.  
Ловушки: `NER_ENABLED=1 python scripts/demo_traps.py` (или `0` — только rules).

## Перед RU (локальный gate)

Ещё **не** готово к сдаче без замера на RU. Локально закрыть:

```bash
chmod +x scripts/pre_ru_check.sh
STORAGE_BACKEND=memory NER_ENABLED=0 uvicorn app.main:app --port 8080 &
./scripts/pre_ru_check.sh
```

Что уже должно быть зелёным локально:
- pytest (rules + holdout + process)
- 68 acceptance (с `NER_ENABLED=0` ФИО через labelled/role)
- create RPS / 100k без падения

Что **только на RU**:
- `load_smoke.py --url https://<host> --n 2000 --concurrency 100`
- `load_smoke.py --url https://<host> --profile 100k ...`
- вписать цифры в слайд/README

## Метрики и нагрузка

- Prometheus: `GET /metrics` (Latency / RPS / TPS)
- Ready: `GET /ready` (проверка state store)
- ML для **demo/proxy**: `CONTEXT_ML_ENABLED=1` + `use_context_ml: true` (RuBERT ∪ точные rules → discourse)
- `/process` (autotest/high_rps): `use_ner: false` — RPS без ML
- ФИО без NER (load): поля `ФИО:` / роль `Клиент Имя Фамилия`
- Локальный smoke нагрузки:
  ```bash
  STORAGE_BACKEND=memory NER_ENABLED=0 uvicorn app.main:app --port 8080
  python scripts/load_smoke.py --n 500 --concurrency 50 --mode create
  python scripts/load_smoke.py --profile 100k --mode create --n 10 --concurrency 2
  ```
- Локальное демо с ML:
  ```bash
  STORAGE_BACKEND=memory NER_ENABLED=1 uvicorn app.main:app --port 8080
  ```
- RU:
  ```bash
  docker compose up --build -d
  python scripts/load_smoke.py --url https://<ru-host> --n 2000 --concurrency 100 --mode create
  python scripts/load_smoke.py --url https://<ru-host> --profile 100k --mode create --n 20 --concurrency 4
  ```

## Документы

| Файл | Зачем |
|---|---|
| [`docs/START_HERE.md`](docs/START_HERE.md) | baseline v1 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | API / Redis / маски |
| [`docs/DETECTION.md`](docs/DETECTION.md) | 17 типов |
| [`docs/acceptance_cases.json`](docs/acceptance_cases.json) | 68 кейсов |
| [`docs/holdout_cases.json`](docs/holdout_cases.json) | независимый holdout |
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
# 68 cases:
NER_ENABLED=0 python scripts/eval_acceptance.py
```

RuBERT (опционально): `NER_ENABLED=1 NER_LOCAL=1` (нужен HF cache / `HF_HUB_OFFLINE=1`).
