#!/usr/bin/env bash
# Build a submission ZIP with sources only — never packs .env / secrets / venv.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HOME/Desktop/alfa_vibe-submission.zip}"
cd "$ROOT"
rm -f "$OUT"
zip -r "$OUT" . \
  -x '.git/*' \
  -x '.venv/*' \
  -x 'venv/*' \
  -x '**/__pycache__/*' \
  -x '**/*.pyc' \
  -x '.pytest_cache/*' \
  -x '.env' \
  -x 'ui/icons/*' \
  -x 'ui/photos/*' \
  -x '.DS_Store' \
  -x '**/.DS_Store' \
  -x 'docs/acceptance_eval_report.json' \
  -x '.cursor/*' \
  -x 'agent-transcripts/*' \
  -x 'models/*'
echo "Wrote $OUT"
if unzip -l "$OUT" | grep -E '(^|/)\.env$'; then
  echo "ERROR: .env leaked into zip"
  exit 1
fi
echo "OK: .env absent from archive"
