# Architecture v2 — 3 detection flows + shared structural layer

Baseline for comparison: `experiment/p1-address-rollback`, external score **9465**.
This branch is an architectural rebuild and is **not** a new accepted scoring baseline yet.

## 1. Canonical product model

The product table defines two independent axes:

1. **Detection method** — how we decide what the PII is.
2. **Structure** — whether a confirmed PII object is atomic or composite.

The canonical evaluator core contains exactly **17 types**.

### Group A — context-defined → ML-first

- PERSON
- PLACE_OF_BIRTH
- CITIZENSHIP
- PASSPORT_ISSUER
- ADDRESS
- CARDHOLDER_NAME

### Group B — format + context → rules-based

- BIRTH_DATE
- PASSPORT
- SUBDIVISION_CODE
- PASSPORT_ISSUE_DATE
- DRIVER_LICENSE
- CVV
- PIN

### Group C — format-defined → rules-based

- EMAIL
- PHONE
- INN
- PAYMENT_CARD

Bonus document types such as SNILS / OMS / international passport remain extensions and are not part of the canonical catalog.

---

## 2. Common pipeline

```text
INPUT TEXT
    │
    ├──────────────────────────────────────────────┐
    │                                              │
    ▼                                              ▼
FORMAT FLOW                                FORMAT+CONTEXT FLOW
rules / parser                            rules / parser
    │                                              │
    │                                     format candidate
    │                                              │
    │                                     context confirmation
    │                                              │
    └──────────────────────┬───────────────────────┘
                           │
                           │
                           ▼
                    CONTEXT ML FLOW
                           │
                     raw NER entities
               PERSON / CITY / COUNTRY /
               REGION / STREET / HOUSE ...
                           │
                           ▼
                   business-role mapping
          PERSON / PLACE_OF_BIRTH / CITIZENSHIP /
             ADDRESS / CARDHOLDER_NAME
                           │
          PASSPORT_ISSUER: explicit temporary
          rules fallback because current RuBERT
          model has no ORG output head
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
       all confirmed                no target role
         candidates                     DROP
             │
             ▼
        STRUCTURAL LAYER
             │
      atomic or composite?
             │
       ┌─────┴───────────┐
       │                 │
       ▼                 ▼
    atomic           composite
    as-is       split semantic parts
                     │
                     ▼
                 eligibility
                     │
                     ▼
              overlap resolver
                     │
                     ▼
                    MASK
```

---

## 3. Flow A — context-defined

```text
TEXT
  │
  ▼
Raw ML NER
  │
  ├─ PERSON-like
  ├─ location/address-like
  └─ other raw labels
  │
  ▼
Business role mapper
  │
  ├─ PERSON + personal/client context → PERSON
  ├─ location + birth context → PLACE_OF_BIRTH
  ├─ COUNTRY + citizenship context → CITIZENSHIP
  ├─ location hierarchy → ADDRESS
  ├─ PERSON + cardholder context → CARDHOLDER_NAME
  └─ no required role → DROP
  │
  ▼
Structural layer
```

**Model limitation:** selected `redmadrobot-rnd/rubert-base-pii-ner` has person, location/address, contacts and document-number labels, but no generic ORG head. Therefore `PASSPORT_ISSUER` remains one isolated fallback detector until the ML adapter is extended/replaced with ORG-capable NER.

The model is not loaded into every API worker. It runs in a dedicated `ner` service and returns raw entities over the internal network.

---

## 4. Flow B — format + context

```text
TEXT
  │
  ▼
Find format candidate
  │
  ├─ invalid → DROP
  └─ valid
       │
       ▼
  target context?
       │
       ├─ no → DROP
       └─ yes
            │
            ▼
       confirmed type
            │
            ▼
       structural layer
```

Each type owns only:
- candidate format;
- contextual confirmation.

It must not own structural decomposition.

---

## 5. Flow C — format-defined

```text
TEXT
  │
  ▼
Find format candidate
  │
  ▼
Validate format/checksum
  │
  ├─ invalid → DROP
  └─ valid
       │
       ▼
explicit service/non-PII exclusion?
       │
       ├─ yes → DROP
       └─ no → confirmed type
                    │
                    ▼
              structural layer
```

Positive semantic context is not required for these four types. Explicit hard-negative/service rules may exclude a valid-looking value.

---

## 6. Structural layer

Structure is no longer detector-owned.

```text
confirmed PII
    │
    ▼
catalog[type].structure
    │
    ├─ ATOMIC → keep one semantic span
    │
    └─ COMPOSITE
          │
          ├─ PERSON → first / middle / last
          ├─ ADDRESS → region/city/street/house/building/flat/index
          ├─ CARDHOLDER_NAME → first / last / middle
          ├─ PASSPORT → series / number
          └─ DRIVER_LICENSE → series / number
    │
    ▼
eligibility + overlap resolver
```

Legacy public detector functions retain structured output for backwards compatibility, but the production v2 flows call structure-agnostic candidate detectors and then one shared `normalize_structures()`.

---

## 7. Runtime topology

```text
                    ┌──────────────┐
request ───────────►│ proxy/API x4 │
                    └──────┬───────┘
                           │
        ┌──────────────────┼─────────────────┐
        │                  │                 │
        ▼                  ▼                 ▼
 format rules       format-context      context ML
                                              │
                                              ▼
                                      ┌──────────────┐
                                      │ NER service  │
                                      │ 1 model copy │
                                      └──────┬───────┘
                                             │ raw entities
                                             ▼
                                      role mapping
        └──────────────────┬──────────────────┘
                           ▼
                    structural layer
                           ▼
                        resolver
                           ▼
                         mask
                           ▼
                         Redis
```

The NER service is a separate image (`Dockerfile.ner`) so 4 API workers do not each load a full transformer model.

---

## 8. Status

Implemented:
- canonical 17-type catalog;
- three explicit flows;
- raw NER interface;
- ML raw-entity → business-role mapping;
- shared structural layer;
- dedicated NER service;
- `/process` mapped to the autotest ML profile;
- compatibility wrappers for old detector/unit-test APIs.

Not yet accepted as scoring baseline:
- external evaluator score;
- latency/RPS with context ML active;
- final decision on ORG-capable model for `PASSPORT_ISSUER`.

Next step after architecture validation:
1. deploy architecture-v2;
2. measure correctness + RPS/latency;
3. only then start one-entity/one-node experiments inside the new architecture.
