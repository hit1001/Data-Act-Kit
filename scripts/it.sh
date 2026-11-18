#!/usr/bin/env bash
# Runs the integration tests against real TimescaleDB and Mosquitto (Docker), then tears them down.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IT_SECRETS="$(mktemp -d)"
export IT_SECRETS
cleanup() { docker compose -f "$ROOT/deploy/docker-compose.it.yml" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
SECRETS_DIR="$IT_SECRETS" "$ROOT/deploy/scripts/init-secrets.sh" >/dev/null
SECRETS_DIR="$IT_SECRETS" "$ROOT/deploy/scripts/device-cert.sh" dev-1 >/dev/null
SECRETS_DIR="$IT_SECRETS" "$ROOT/deploy/scripts/device-cert.sh" dev-2 >/dev/null
docker compose -f "$ROOT/deploy/docker-compose.it.yml" up -d --wait db mosquitto
docker compose -f "$ROOT/deploy/docker-compose.it.yml" run --rm mqtt-provision >/dev/null
cd "$ROOT"
NODE_EXTRA_CA_CERTS="$IT_SECRETS/certs/ca.crt" DAK_IT=1 node --test --test-concurrency=1 \
  --test-reporter=spec --test-reporter-destination=stdout --test-reporter=tap --test-reporter-destination=it.tap \
  "packages/server/test/it/*.test.ts"
