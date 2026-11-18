#!/usr/bin/env bash
# Creates the deployment's secrets and TLS material in deploy/secrets (never committed). Idempotent:
# existing files are kept, so re-running never rotates a key that encrypted data depends on.
set -euo pipefail
S="${SECRETS_DIR:-$(cd "$(dirname "$0")/.." && pwd)/secrets}"
mkdir -p "$S/certs" && chmod 700 "$S"
hex() { [ -s "$S/$1" ] || openssl rand -hex 32 > "$S/$1"; }
pw()  { [ -s "$S/$1" ] || openssl rand -base64 30 | tr -d '/+=\n' > "$S/$1"; }
hex kek.hex; hex fingerprint.hex
pw db_password; pw mqtt_admin_password; pw mqtt_service_password; pw keycloak_admin_password; pw keycloak_dak_admin_secret; pw mavt_password
[ -e "$S/mavt_api_key" ] || : > "$S/mavt_api_key"   # filled once MAVT is running (README)
if [ ! -s "$S/certs/ca.crt" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=dataact-kit CA" \
    -keyout "$S/certs/ca.key" -out "$S/certs/ca.crt"
fi
if [ ! -s "$S/certs/broker.crt" ]; then
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=mosquitto" -keyout "$S/certs/broker.key" -out "$S/certs/broker.csr"
  openssl x509 -req -in "$S/certs/broker.csr" -CA "$S/certs/ca.crt" -CAkey "$S/certs/ca.key" -CAcreateserial -days 825 \
    -extfile <(printf "subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") -out "$S/certs/broker.crt"
  rm "$S/certs/broker.csr"
fi
chmod 644 "$S"/certs/*.crt "$S"/certs/broker.key   # read by the mosquitto user inside its container
echo "Secrets ready in $S"
