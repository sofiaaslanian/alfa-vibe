#!/usr/bin/env bash
# Local gate before RU deploy. Does NOT hit production.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

echo "== NER=0 quality suite =="
NER_ENABLED=0 pytest -q

echo "== acceptance 68 (rules-only) =="
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 NER_ENABLED=0 STORAGE_BACKEND=memory \
  python scripts/eval_acceptance.py | tail -n 35

echo "== server readiness =="
if ! curl -sf http://127.0.0.1:8080/ready >/dev/null; then
  echo "Start the Redis-backed server first:"
  echo "  docker compose up --build -d"
  exit 1
fi

echo "== short round-trip load =="
python scripts/load_smoke.py --n 400 --concurrency 40 --mode pair

echo "== 100k round-trip load =="
python scripts/load_smoke.py --profile 100k --mode pair --n 4 --concurrency 2

echo "== resource snapshot =="
if command -v redis-cli >/dev/null 2>&1; then
  redis-cli -u "${REDIS_URL:-redis://127.0.0.1:6379/0}" INFO memory \
    | grep -E 'used_memory_human|maxmemory_human|mem_fragmentation_ratio' || true
fi
ps -eo pid,pcpu,pmem,rss,command | grep '[u]vicorn' || true

echo "OK — local gate passed. Next: repeat against the RU URL."
