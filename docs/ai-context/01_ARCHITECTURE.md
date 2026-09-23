# Архитектура

Фактическая схема текущего `main`.

```text
AlfaSonar / клиент
  -> POST /process          (без API-ключа, без LLM)
       -> ProcessService.process
            -> правила (профиль autotest, use_context_ml: false)
            -> Redis: состояние операции + кэш маски
            -> dev_redact_v1
       <- {"result": "..."}

Демо UI / потребитель
  -> POST /demo/run или POST /proxy/chat   (X-API-Key, X-System)
       -> detect (для demo: правила + NER sidecar)
       -> маска (demo: scoped token, autotest/high_rps: звёздочки)
       -> опционально AlfaGen LLM, только уже замаскированный текст
       -> demask, если у системы allow_demask: true

Caddy (docker-compose.yml)
  -> HTTPS на proxy:8080
Публичный сервер без домена (docker-compose.http.yml)
  -> порт 80 напрямую на proxy:8080, без Caddy
```

Отдельного процесса с именем Proxy нет. Сервис в Compose называется `proxy`, код — FastAPI в `app/api.py`.

## Компоненты

### proxy (API)

- Назначение: HTTP-контракт, демо, метрики.
- Файлы: `app/main.py`, `app/api.py`, `Dockerfile`.
- Вход: HTTP 8080.
- Выход: JSON или HTML UI.
- Зависит от Redis и, при включённом context ML, от сервиса `ner`.
- Образ без torch. В runtime `USER app`.

### processing

- Назначение: маска, демаскирование, политика системы, кэш повторов.
- Файл: `app/process.py`.
- Вход: текст, `payload_id`, имя системы.
- Выход: строка `result` либо `ProcessError` со статусом.
- `POST /process` без заголовка `X-System` идёт в профиль `autotest`.

### detection

- Назначение: найти спаны ПД.
- Файлы: `app/pii/detect.py`, `flows.py`, `rules.py`, `discourse.py`, `context_ml.py`, `parts.py`, `structural.py`.
- Три потока в `flows.py`: формат (email, телефон, ИНН, карта), формат с контекстом (даты, паспорт, ВУ, CVV, PIN), контекст (ФИО, адрес и роли). Если ML выключен, контекст берёт только правила.

### NER sidecar

- Назначение: локальный RuBERT, сырые сущности.
- Файлы: `app/ner_api.py`, `app/pii/ner.py`, `Dockerfile.ner`.
- Вход: `POST /detect` `{text}`. Выход: `{entities}`.
- Модель: `redmadrobot-rnd/rubert-base-pii-ner`.
- Proxy ходит на `NER_URL` (в Compose `http://ner:8090`) и не грузит torch.

### Redis

- Назначение: общее состояние нескольких воркеров.
- Файл: `app/state.py`. Образ `redis:7.4.11-alpine`.
- Порт 6379 наружу не публикуется.
- Ключи live/seen и кэш маски по HMAC текста. Соответствие шифруется AES-GCM (`app/crypto_util.py`).

### Caddy

- Назначение: TLS, если заданы `DOMAIN` и `ACME_EMAIL`.
- Файлы: `Caddyfile`, сервис `caddy` в `docker-compose.yml`.
- Текущий публичный стенд Selectel поднят через `docker-compose.http.yml` и Caddy не использует.

### LLM-клиент

- Файл: `app/llm.py`.
- Вызывается из `/proxy/chat` и `/demo/run`, не из `/process`.
- URL и модель по умолчанию: `https://alfagen.alfabank.ru/continue-dev/`, `deepseek-ai/DeepSeek-V4-Flash-0731`.
