FROM python:3.11.16-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NER_ENABLED=0 \
    STORAGE_BACKEND=redis \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY app ./app
COPY config.yaml .
COPY scripts ./scripts
COPY ui ./ui
RUN python -m zipfile -e ui/icons.zip ui/icons \
    && python -m zipfile -e ui/photos.zip ui/photos
COPY docs/acceptance_cases.json docs/holdout_cases.json docs/acceptance_summary.json \
     docs/load_results.json docs/criteria_checklist.json ./docs/
EXPOSE 8080

# Multi-worker; Redis required for shared state (see docker-compose).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
