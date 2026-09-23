# Проверка

Команды ниже сняты с `README.md`, `.github/workflows/ci.yml` и скриптов. «Проверено» стоит только там, где команда выполнена на baseline `e79f468` в этой сессии. Остальное — как запускать, без утверждения, что оно зелёное.

Рабочий каталог — корень репозитория. Интерпретатор, которым гонялись локальные тесты: `D:\alfa-work\venv\Scripts\python` (зависимости уже стояли).

## Установка

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --require-hashes -r requirements.lock
```

Ожидание: пакеты из lock ставятся без ошибки. В этой сессии заново не ставились.

NER отдельно, он тяжёлый и для `/process` не нужен:

```bash
pip install -r requirements-ner.txt
```

В этой сессии не запускалось.

## Тесты

Как в CI (`.github/workflows/ci.yml`):

```bash
set STORAGE_BACKEND=memory
set NER_ENABLED=0
set ALLOW_WEAK_STATE_KEYS=1
pytest -q
```

Проверено 2026-09-23 на `e79f468`: `383 passed, 1 skipped`.

Приёмка на внутреннем наборе:

```bash
set NER_ENABLED=0
python scripts/eval_acceptance.py
```

Проверено в той же сессии: `cases: 67/68 (0.9853)`, `mask_accuracy: 0.9853`, `roundtrip: 1.0`. Единственный провал: `DRIVER_LICENSE_NUMBER_1`. Скрипт ещё пишет `docs/acceptance_eval_report.json` (файл в `.gitignore`). HTTP-проверка внутри скрипта на `http://127.0.0.1:8080` в этой сессии не поднята: соединение отклонено. Это не провал кейсов.

## Docker

```bash
docker compose up --build -d
```

Поднимет redis, ner, proxy и caddy. Caddy требует `DOMAIN` и `ACME_EMAIL` в `.env`. В этой сессии полный compose заново не собирался.

Публичный стенд без домена, как в `docker-compose.http.yml`:

```bash
docker compose -f docker-compose.yml -f docker-compose.http.yml up -d --build redis proxy
```

NER всё равно стартует: `proxy` зависит от него. В этой сессии образ proxy на сервере уже был пересобран с `e79f468` до начала handoff. Повторный build здесь не делался.

## Health

```bash
curl -fsS http://127.0.0.1:8080/ready
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/metrics
```

Ожидание `/ready`: `{"status":"ready"}`. Ожидание `/health`: `status=ok`. `/metrics` — текст Prometheus с `alfa_process_latency_seconds`, `alfa_process_total`, `alfa_tokens_total`.

Проверено на публичном стенде `http://135.106.220.67` (порт 80, тот же процесс):

- `/ready` → `{"status":"ready"}`
- `/health` → `{"status":"ok","systems":5,"pd_types":17,"storage":"redis"}`

`/metrics` в этой сессии по сети не запрашивался.

## Smoke API

Маска и восстановление. Второй запрос должен вернуть исходную строку. Подставьте маску из первого ответа, не пример из README.

```bash
curl -sS -X POST http://127.0.0.1:8080/process -H "Content-Type: application/json" -d "{\"payload\":\"Client mailbox is demo.user@example.com\",\"payload_id\":\"smoke-1\"}"
```

На публичном стенде такой цикл для фейкового email уже проходил до этого handoff (коды 200, восстановление совпало). В этой сессии curl на `/process` заново не гонялся.

Локальный smoke нагрузки из README в этой сессии не запускался:

```bash
python scripts/load_smoke.py --n 500 --concurrency 50 --mode create
```
