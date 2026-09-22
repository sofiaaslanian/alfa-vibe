#!/usr/bin/env bash
# Local gate before RU deploy. Does NOT hit production.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

echo "== unit/holdout =="
NER_ENABLED=0 pytest -q

echo "== acceptance 68 (rules; NER off — FIO via labelled/role) =="
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 NER_ENABLED=0 STORAGE_BACKEND=memory \
  python scripts/eval_acceptance.py | tail -n 35

echo "== start local server if needed =="
if ! curl -sf http://127.0.0.1:8080/ready >/dev/null; then
  echo "Start server first:"
  echo "  STORAGE_BACKEND=memory NER_ENABLED=0 uvicorn app.main:app --port 8080"
  exit 1
fi

echo "== load smoke =="
python scripts/load_smoke.py --n 300 --concurrency 40 --mode create
python scripts/load_smoke.py --profile 100k --mode create --n 5 --concurrency 2

echo "OK — local gate passed. Next: deploy to RU and re-run load_smoke with --url https://<host>"
