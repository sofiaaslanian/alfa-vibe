#!/usr/bin/env bash
# Build a source-only submission ZIP for Sonar/code review.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HOME/Desktop/alfa_vibe-submission.zip}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cd "$ROOT"
rm -f "$OUT"

mkdir -p "$STAGE/app" "$STAGE/scripts" "$STAGE/tests" "$STAGE/ui/js" "$STAGE/docs"

cp -R app/. "$STAGE/app/"
cp -R scripts/. "$STAGE/scripts/"
cp -R tests/. "$STAGE/tests/"
cp ui/*.html ui/*.css ui/*.js "$STAGE/ui/" 2>/dev/null || true
cp -R ui/js/. "$STAGE/ui/js/" 2>/dev/null || true

for f in Dockerfile docker-compose.yml config.yaml pytest.ini requirements.txt requirements-ner.txt README.md .dockerignore .gitignore .env.example; do
  [ -f "$f" ] && cp "$f" "$STAGE/$f"
done

# Small documentation/evidence files only. No xlsx, zip, images, datasets, dumps.
for f in docs/START_HERE.md docs/ARCHITECTURE.md docs/DETECTION.md docs/HACKATHON_BRIEF.md; do
  [ -f "$f" ] && cp "$f" "$STAGE/docs/"
done

find "$STAGE" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$STAGE" -type f \( -name '*.pyc' -o -name '.DS_Store' -o -name '*.zip' -o -name '*.xlsx' \) -delete

(
  cd "$STAGE"
  zip -qr "$OUT" .
)

echo "Wrote $OUT"

# Hard fail if forbidden artifacts slipped in.
if unzip -Z1 "$OUT" | grep -E '(^|/)(\.env|\.git|\.venv|venv|node_modules|__pycache__)(/|$)|\.(zip|xlsx|png|jpg|jpeg|gif|webp|pyc)
  echo "ERROR: forbidden artifact found in submission ZIP"
  exit 1
fi

echo "OK: source-only archive; no secrets, media archives, binary media, xlsx or caches"
; then
  echo "ERROR: forbidden artifact found in submission ZIP"
  exit 1
fi

echo "OK: source-only archive; no secrets, media archives, binary media, xlsx or caches"
