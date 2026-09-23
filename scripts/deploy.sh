#!/usr/bin/env bash
# Deploy the ALFAGEN PII service to a fresh VDS (Selectel) with a public domain.
#
# Safe by design:
#   - idempotent: safe to re-run; existing .env is never overwritten
#   - never prints secrets
#   - only touches this project's files
#
# Usage (run on the server, inside the repo):
#   DOMAIN=example.ru ACME_EMAIL=you@example.ru ./scripts/deploy.sh
#
# Optional env overrides:
#   DOMAIN, ACME_EMAIL, PROXY_API_KEYS, STATE_HMAC_KEY, STATE_ENC_KEY
#   CONTEXT_ML_ENABLED (default 1), PROCESS_CONCURRENCY (default 180)
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- 0. Preconditions -------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found. Install it first: curl -fsSL https://get.docker.com | sh"
command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
  || die "docker compose plugin not found."

DOMAIN="${DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
if [[ -z "$DOMAIN" ]]; then
  die "DOMAIN is required. Run: DOMAIN=example.ru ACME_EMAIL=you@example.ru ./scripts/deploy.sh"
fi

# --- 1. .env ----------------------------------------------------------------
if [[ ! -f .env ]]; then
  log "Creating .env from .env.example"
  cp .env.example .env
  # Fill required values; keep existing placeholders if not provided.
  sed -i "s|^DOMAIN=.*|DOMAIN=$DOMAIN|" .env
  if [[ -n "$ACME_EMAIL" ]]; then
    sed -i "s|^ACME_EMAIL=.*|ACME_EMAIL=$ACME_EMAIL|" .env
  fi
  # Generate fresh secrets if the placeholders are still default.
  gen() { python3 -c "import secrets; print(secrets.token_hex(32))"; }
  if grep -q '^STATE_HMAC_KEY=change-me-hmac' .env; then
    sed -i "s|^STATE_HMAC_KEY=.*|STATE_HMAC_KEY=$(gen)|" .env
  fi
  if grep -q '^STATE_ENC_KEY=change-me-enc' .env; then
    sed -i "s|^STATE_ENC_KEY=.*|STATE_ENC_KEY=$(gen)|" .env
  fi
  if grep -q '^PROXY_API_KEYS=change-me-demo-key' .env; then
    sed -i "s|^PROXY_API_KEYS=.*|PROXY_API_KEYS=$(gen)|" .env
  fi
  log ".env created. Review it: nano .env"
else
  log ".env already exists — leaving it untouched."
fi

# --- 2. Build & start -------------------------------------------------------
log "Building and starting services (redis, ner, proxy, caddy)"
docker compose up -d --build

# --- 3. Wait for readiness --------------------------------------------------
log "Waiting for proxy to become ready"
ready=0
for i in $(seq 1 60); do
  if docker compose exec -T proxy python -c \
      "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/ready', timeout=3)" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  die "proxy did not become ready in 120s. Check: docker compose logs proxy"
fi
log "proxy is ready."

# --- 4. Public smoke tests --------------------------------------------------
BASE="https://$DOMAIN"
log "Smoke test: /ready"
curl -fsS "$BASE/ready" && echo

log "Smoke test: driver license (expected: серия ** **, номер ******)"
curl -fsS -X POST "$BASE/process" \
  -H "Content-Type: application/json" \
  -d '{"payload":"Водительское удостоверение: серия 77 11, номер 123456","payload_id":"deploy-vu-1"}'
echo

log "Smoke test: passport (expected: серия ****, номер ******)"
curl -fsS -X POST "$BASE/process" \
  -H "Content-Type: application/json" \
  -d '{"payload":"Паспорт клиента: серия 4510, номер 123456","payload_id":"deploy-pass-1"}'
echo

log "Deploy OK. Services:"
docker compose ps