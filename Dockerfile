FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NER_ENABLED=0 \
    STORAGE_BACKEND=redis \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config.yaml .
COPY scripts ./scripts
COPY docs/acceptance_cases.json docs/holdout_cases.json ./docs/
COPY .env.example .

EXPOSE 8080

# Multi-worker; Redis required for shared state (see docker-compose).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
