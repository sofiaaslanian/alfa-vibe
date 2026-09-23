# Architecture v2 — 3 PII flows + structural layer

Baseline for the refactor: scorer-best branch 9465 (experiment/p1-address-rollback).

The architecture has two independent axes:

1. How the value is identified — one of three detection groups.
2. How the confirmed value is structured — atomic or composite.

The structural decision is made after the PII type is confirmed.

## 1. Canonical 17 types

| PII type | Internal type | Detection group | Structure |
|---|---|---|---|
| ФИО | PERSON | Context / ML | Composite |
| Место рождения | PLACE_OF_BIRTH | Context / ML | Atomic |
| Гражданство | CITIZENSHIP | Context / ML | Atomic |
| Орган, выдавший паспорт | PASSPORT_ISSUER | Context / ML | Atomic |
| Адрес | ADDRESS | Context / ML | Composite |
| Имя держателя карты | CARDHOLDER_NAME | Context / ML | Composite |
| Дата рождения | BIRTH_DATE | Format + context / rules | Atomic |
| Серия и номер паспорта | PASSPORT | Format + context / rules | Composite |
| Код подразделения | SUBDIVISION_CODE | Format + context / rules | Atomic |
| Дата выдачи паспорта | PASSPORT_ISSUE_DATE | Format + context / rules | Atomic |
| Серия и номер ВУ | DRIVER_LICENSE | Format + context / rules | Composite |
| CVV | CVV | Format + context / rules | Atomic |
| PIN | PIN | Format + context / rules | Atomic |
| Email | EMAIL | Format / rules | Atomic |
| Телефон | PHONE | Format / rules | Atomic |
| ИНН | INN | Format / rules | Atomic |
| Номер банковской карты | PAYMENT_CARD | Format / rules | Atomic |

Core evaluator pipeline contains exactly these 17 types. SNILS / OMS / international passport remain optional extensions outside the canonical core flow and are not executed by the three canonical flows.

## 2. Common pipeline

~~~mermaid
flowchart TD
    A[Input text] --> B1[FORMAT flow]
    A --> B2[FORMAT + CONTEXT flow]
    A --> B3[CONTEXT ML flow]

    B1 --> C[Confirmed PII findings]
    B2 --> C
    B3 --> C

    C --> D[Shared structural layer]
    D --> E[Policy / eligibility]
    E --> F[Overlap resolver]
    F --> G[Mask]
    G --> H[Encrypted state]
    H --> I[Result]
~~~

The three detection flows answer what PII object has been confirmed.
The structural layer answers which semantic parts of that object are masked.

## 3. Flow A — format-defined

Types: EMAIL, PHONE, INN, PAYMENT_CARD.

~~~mermaid
flowchart TD
    A[Text] --> B[Find format candidate]
    B --> C{Format valid?}
    C -- No --> X[Drop]
    C -- Yes --> D{Explicit exclusion?}
    D -- Yes --> X
    D -- No --> E[Confirmed PII]
~~~

| Type | Candidate | Validation | Explicit exclusions |
|---|---|---|---|
| EMAIL | email syntax | malformed leftovers | service/local roles |
| PHONE | RU / international patterns | RU normalization / length | public-service phone / negative role |
| INN | 12 digits | INN checksum | explicit non-personal role |
| PAYMENT_CARD | 13–19 digits | Luhn; guarded fallback | order/operation/etc. roles |

Rule: a positive business label is not required for this group. Format is primary evidence.

## 4. Flow B — format + context

Types: BIRTH_DATE, PASSPORT, SUBDIVISION_CODE, PASSPORT_ISSUE_DATE, DRIVER_LICENSE, CVV, PIN.

~~~mermaid
flowchart TD
    A[Text] --> B[Find format candidate]
    B --> C{Format valid?}
    C -- No --> X[Drop]
    C -- Yes --> D[Context / role classifier]
    D --> E{Target role confirmed?}
    E -- No --> X
    E -- Yes --> F[Confirmed PII]
~~~

| Type | Format candidate | Context confirmation |
|---|---|---|
| BIRTH_DATE | numeric/text date | birth role |
| PASSPORT | 10-digit passport shapes | passport anchor |
| SUBDIVISION_CODE | XXX-XXX | subdivision role |
| PASSPORT_ISSUE_DATE | numeric/text date | passport-issue role |
| DRIVER_LICENSE | 10-digit VU shapes | VU anchor |
| CVV | 3–4 digits | CVV/CVC/security-code role |
| PIN | 4–6 digits | card PIN role |

Candidate detection and role confirmation are logically separate even when a legacy regex currently performs both operations in one function.

## 5. Flow C — context-defined / ML-first

Types: PERSON, PLACE_OF_BIRTH, CITIZENSHIP, PASSPORT_ISSUER, ADDRESS, CARDHOLDER_NAME.

~~~mermaid
flowchart TD
    A[Text] --> B[NER / ML entity extraction]
    B --> C[Raw semantic entity]
    C --> D[Context role mapping]
    D --> E{PII business role?}
    E -- No --> X[Drop]
    E -- Yes --> F[Canonical PII type]
~~~

The ML layer is two-stage:

1. NER detects a generic semantic entity: PERSON / CITY / STREET / ORG / COUNTRY / etc.
2. Context-role mapping turns that entity into one of the six business PII types.

Examples:

    PERSON + "имя держателя карты" -> CARDHOLDER_NAME
    PERSON + customer/self claim    -> PERSON
    CITY + "место рождения"        -> PLACE_OF_BIRTH
    COUNTRY + "гражданство"        -> CITIZENSHIP
    ORG + "паспорт выдан"          -> PASSPORT_ISSUER
    CITY/STREET/HOUSE + address role -> ADDRESS

Important contract: when ML is enabled for a request, an empty ML result is authoritative for every type the selected model can express. The pipeline does not silently replace an ML miss with legacy context rules.

Current model coverage is 5/6 context types: PERSON, PLACE_OF_BIRTH, CITIZENSHIP, ADDRESS, CARDHOLDER_NAME. The selected RuBERT model has no ORG label, so PASSPORT_ISSUER has one explicit temporary rules fallback. This fallback is isolated and should disappear when an ORG-capable context model is connected.

When context ML is disabled entirely, old labelled rules act as compatibility fallback for the whole context group.

## 6. Shared structural layer

~~~mermaid
flowchart TD
    A[Confirmed PII] --> B{Structure}
    B -- Atomic --> C[Keep one semantic span]
    B -- Composite --> D[Structural parser]
    D --> E[Semantic component spans]
    C --> F[Resolver]
    E --> F
    F --> G[Mask]
~~~

| Type | Components |
|---|---|
| PERSON | first / middle / last |
| ADDRESS | city / street / house / building / flat / index |
| CARDHOLDER_NAME | first / last |
| PASSPORT | series / number |
| DRIVER_LICENSE | series / number |

Detector functions return a confirmed object span. Composite splitting lives in app/pii/structural.py rather than inside the group-specific identification decision.

## 7. Code map

| Responsibility | File |
|---|---|
| canonical 17-type catalog | app/pii/catalog.py |
| three detection flows | app/pii/flows.py |
| raw NER → business role | app/pii/context_ml.py |
| ML / NER adapter | app/pii/ner.py |
| shared structural layer | app/pii/structural.py |
| eligibility + overlap resolver | app/pii/detect.py |
| rule implementations | app/pii/rules.py, app/pii/ids/* |
| system routing | app/process.py, config.yaml |
| evaluator endpoint | app/api.py |

## 8. Runtime routing

System config decides whether it wants context ML:

- autotest: use_context_ml = true
- demo: true
- format_only: false
- high_rps: false

A deployment master switch must also be enabled:

    CONTEXT_ML_ENABLED=1
    CONTEXT_ML_FAIL_CLOSED=1

Legacy NER_ENABLED / NER_FAIL_CLOSED remain compatibility aliases.

Routing:

    context type needed?
      no -> no ML
      yes
        -> master switch enabled?
            no -> compatibility rules
            yes
              -> system use_context_ml?
                  false -> compatibility rules
                  true -> authoritative ML context flow

If required context ML raises an error in the target profile, the request fails closed. It does not silently switch to rules. An explicit fail-open mode exists only as a compatibility option.

## 9. Current deployment boundary

The default slim Docker image historically installs only requirements.txt.
Local RuBERT dependencies live in requirements-ner.txt.

Architecture v2 therefore supports two deployment modes:

- the default docker-compose target: a dedicated NER sidecar built from Dockerfile.ner, with the API calling it through NER_URL;
- an optional external/remote NER_URL with the same raw-entity contract.

The sidecar loads the model before it becomes healthy, while the API image stays slim. Context ML is active only when the sidecar/external endpoint is available and CONTEXT_ML_ENABLED=1.

## 10. Experiment discipline

After v2:

one experiment = one entity × one decision node in its flow or structural layer.

Examples:

- BIRTH_DATE × context-role node
- PAYMENT_CARD × format validator
- ADDRESS × structural parser
- PERSON × context-role mapping

Never change two entity types or two decision nodes in one scorer experiment.
