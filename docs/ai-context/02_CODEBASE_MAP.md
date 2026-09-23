# Карта кода

Критичность: высокая — ломает контракт AlfaSonar или демо; средняя — ломает качество маски или стенд; низкая — UI и отчёты.

## Контракт и HTTP

`app/main.py`
- Точка входа uvicorn: экспортирует `app`.
- Критичность: высокая.

`app/api.py`
- Маршруты и модели запроса.
- `POST /process` — автотест. Ключ не проверяет. Без `X-System` система = `autotest`. Обработка в `asyncio.to_thread`. При занятости семафора `PROCESS_CONCURRENCY` — `429` и `Retry-After: 1`.
- `POST /proxy/chat` — маска, опциональный вызов AlfaGen, demask. Нужен `X-API-Key`.
- `POST /demo/run`, `GET /demo/config`, `GET /demo/evidence` — UI.
- `GET /health`, `GET /ready`, `GET /metrics`, `GET /systems`.
- `GET /` и `GET /evidence` — HTML.
- Вызывается из `app/main.py`. Критичность: высокая.

`app/process.py`
- `ProcessService.process` — путь `/process`.
- `proxy_protect` / `proxy_restore` — путь proxy и demo.
- `_context_ml_for_system` решает, звать ли NER.
- Кэш маски в процессе и в Redis, чтобы повтор того же текста не считал детектор заново.
- Критичность: высокая.

`app/config.py` + `config.yaml`
- Системы, типы, `mask_style`, `use_context_ml`, `combo_require`.
- Критичность: высокая. Пустой `pd_types` означает «все типы по умолчанию».

`app/state.py`
- `MemoryStateStore` и `RedisStateStore`.
- `create_atomic` — один live-ключ на `payload_id`.
- `lookup_for_mask`, `commit_new_mask`, `get_cached_mask`.
- Критичность: высокая.

`app/crypto_util.py`
- HMAC и AES-GCM. Ключи `STATE_HMAC_KEY`, `STATE_ENC_KEY`.
- Критичность: высокая. Слабый ключ при Redis запрещён, если нет `ALLOW_WEAK_STATE_KEYS=1`.

`app/masking.py`
- `apply_dev_redact` — звёздочки, стратегия автотеста.
- `apply_scoped_tokens` / `restore_scoped_tokens` — токены proxy.
- Критичность: высокая.

`app/llm.py`
- `AlfaGenClient.chat`. Критичность: средняя. На score `/process` не влияет.

## Детектор

`app/pii/detect.py`
- `Finding`, `detect_pii`, перекрытия, решение mask/allow, вызов ML.
- Критичность: высокая.

`app/pii/flows.py`
- `FormatFlow`, `FormatContextFlow`, `ContextFlow`, `run_detection_flows`.
- Критичность: высокая.

`app/pii/rules.py`
- Правила по типам. Самый большой файл детектора.
- Критичность: высокая.

`app/pii/discourse.py`
- Клиентский контекст против ловушек (поэт, служебный адрес).
- Критичность: высокая для критерия ложных срабатываний.

`app/pii/context_ml.py`
- Ответ NER превращает в `Finding` только для контекстных типов.
- Критичность: высокая для `demo`, не для текущего `/process` (`autotest.use_context_ml: false`).

`app/pii/ner.py` + `app/ner_api.py`
- Локальная модель и HTTP sidecar. `_jsonable` приводит `numpy` к JSON.
- Критичность: высокая, если ML включён. Иначе sidecar нужен Compose, потому что `proxy` ждёт healthy `ner`, но `/process` его не вызывает.

`app/pii/parts.py`, `structural.py`, `validate.py`, `ids/card.py`, `ids/inn.py`, `checksums.py`
- Части ФИО и адреса, контрольные суммы, Луна.
- Критичность: высокая для точности маски.

`app/pii/catalog.py`, `claims.py`, `public_figures.py`, `public_contacts.py`
- Справочники ролей, известных имён и служебных телефонов.
- Критичность: средняя или высокая в зависимости от типа.

## Запуск

`Dockerfile`, `Dockerfile.ner`
- Образы API и NER. Оба заканчивают работу как `USER app`.

`docker-compose.yml`
- redis, ner, proxy, caddy. Proxy зависит от healthy redis и ner.

`docker-compose.http.yml`
- Публикует proxy на `80:8080` без Caddy. Так поднят стенд без домена.

`Caddyfile`
- Шаблон TLS. Критичность: низкая для текущего HTTP-стенда.

`.env.example`
- Имена переменных. Не секрет. Критичность: высокая как контракт окружения.

## Проверки

`scripts/eval_acceptance.py`
- 68 кейсов из `docs/acceptance_cases.json`. Считает маску, спаны и roundtrip.
- Критичность: высокая как внутренний регрессионный прогон, не как датасет Альфы.

`scripts/load_smoke.py`
- Локальный или удалённый замер `/process`.
- Критичность: средняя.

`tests/`
- pytest. CI: `.github/workflows/ci.yml`, `NER_ENABLED=0`, `STORAGE_BACKEND=memory`.
- Критичность: высокая.

`ui/`
- Демо-страница. На score `/process` не влияет. В архиве лежат `ui/icons.zip` и `ui/photos.zip`.
