FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NER_ENABLED=0 \
    STORAGE_BACKEND=redis \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

RUN apt-get update && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config.yaml .
COPY scripts ./scripts
COPY ui ./ui

# Full repository contains demo media as ZIPs; source-only submission may omit them.
# Build must still succeed in both cases.
RUN set -eux; \
    if [ -f ui/icons.zip ]; then unzip -q -o ui/icons.zip -d ui/icons; fi; \
    if [ -f ui/photos.zip ]; then unzip -q -o ui/photos.zip -d ui/photos; fi

COPY docs/acceptance_cases.json docs/holdout_cases.json docs/acceptance_summary.json \
     docs/load_results.json docs/criteria_checklist.json ./docs/
COPY .env.example .

EXPOSE 8080

# Multi-worker; Redis required for shared state (see docker-compose).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4", "--no-access-log"]
