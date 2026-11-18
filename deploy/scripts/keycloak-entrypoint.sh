#!/bin/sh
# Reads Keycloak's secrets from Docker secrets, then starts it and imports the realm on first run.
set -eu
KC_DB_PASSWORD="$(cat /run/secrets/db_password)"
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/secrets/keycloak_admin_password)"
KC_DAK_ADMIN_SECRET="$(cat /run/secrets/keycloak_dak_admin_secret)"
export KC_DB_PASSWORD KC_BOOTSTRAP_ADMIN_PASSWORD KC_DAK_ADMIN_SECRET
exec /opt/keycloak/bin/kc.sh start --import-realm
