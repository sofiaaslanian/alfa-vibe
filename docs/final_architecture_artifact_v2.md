# Архитектура: модуль безопасности ПД (AlfaGen)

Цель: пройти `/process` (AlfaSonar) + demo proxy «потребитель → mask → LLM → unmask».

Detection-детали: `PII_DETECTION_ARCHITECTURE.md`.

---

## 1. Два входа → одно ядро

| Вход | Зачем | Маскирование |
|---|---|---|
| `POST /process` | автотест | reference-aligned маски |
| Demo Proxy | живое демо | scoped tokens `<TYPE_n>` |

```text
/process  ─┐
           ├→ detect → resolve → mask/tokenize → state
Proxy    ─┘                              ↓
                                    LLM (только proxy)
```

---

## 2. `/process`

```http
POST /process
{"payload":"<str>","payload_id":"<id>"} → {"result":"<str>"}
```

Без `system_id` / API-key в обязательном контракте.

| Ситуация | Результат |
|---|---|
| Новый id + текст | mask + atomic save |
| Тот же id + тот же original | retry → та же маска |
| Тот же id + маска | demask → original |
| Тот же id + чужой payload | `409` |
| Нет ПД | текст без изменений + state |
| State down | `503`, текст дальше не уходит |

State key: `autotest:{payload_id}` · proxy: `proxy:{consumer}:{op}`.

Алгоритм: HMAC(payload) → compare fingerprints → SET NX / CAS при create. Mappings шифруются, TTL покрывает прогон+retries. Полный plaintext не дублируем, если восстанавливается из маски+mappings.

---

## 3. Detection (кратко)

| Группа | Подход |
|---|---|
| Format | Rules: email / phone / INN / card |
| Context | NER `rubert-base-pii-ner` (allowlist → PERSON) |
| Format-context | Rules (+ optional LLM fallback) |

Порядок: format rules → format-context rules → NER (если нужно) → eligibility → resolver → mask.

Finding: `{type,start,end,score,detector}`. HF только download weights.

---

## 4. Две стратегии маски

**`/process`:** эталонные маски, сохранить пробелы/пунктуацию, линейный проход по spans (не цепочка `.replace`).

**Proxy:** непредсказуемые scoped tokens на операцию; восстанавливать только выпущенные; чужой/сломанный токен не угадывать.

---

## 5. Proxy flow

```text
auth + policy → detect + tokenize → save state → LLM(safe prompt)
→ optional response DLP → demask allowed tokens → client
```

Fail closed: ошибка detect/state/policy → в LLM не шлём.

Коды: `200` · `400` · `409` · `429`+Retry-After · `503`.

---

## 6. Компоненты

| Компонент | Роль |
|---|---|
| `autotest_api` / `proxy_api` | два HTTP-входа |
| `format_rules` / `format_context_rules` | deterministic detect |
| `ner_service` + `ner_client` | RuBERT `/detect` |
| `eligibility` / `span_resolver` | filter + overlaps |
| `mask_strategies` / `state_store` / `restorer` | mask + round-trip |
| `llm_client` | только safe prompt |

```text
app/pii/rules|ner|pipeline   services/ner/   policies/*.yaml
```

---

## 7. Тесты P0

Mask → demask byte-to-byte · retry mask/demask · race два worker'а · `409` · без ПД · overlaps · state `503` · нет PII в логах.

P1: Пушкин-поэт · адрес банка · 100k tokens · RPS/latency · LLM переставила токены.

Цель нагрузки: p95 ≤ 0.5 с @ RPS 1000 (замерять факт).

---

## 8. Шаги

1. Контракт + каркас `/process`  
2. State machine + P0 tests  
3. Rules 17 типов + NER opt-in  
4. Две mask strategy  
5. Demo proxy + AlfaGen  
6. Load/metrics  
7. README + demo script  

---

## 9. DoD

- [ ] `/process` + proxy разделены; atomic state  
- [ ] 17 типов нужным классом; ADDRESS = rules  
- [ ] RuBERT local + allowlist; LLM не hot path  
- [ ] Round-trip exact; fail closed; no PII in logs  
- [ ] Fine-tune NER без смены API  

Открыто у организаторов: эталон масок, SLA перцентиль, TTL demask — до ответа конфигурируемо.
