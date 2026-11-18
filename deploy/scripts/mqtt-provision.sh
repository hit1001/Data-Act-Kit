#!/bin/sh
# Runs inside the mosquitto image. Initialises dynamic security once, then (re)applies the service role.
set -eu
F=/mosquitto/data/dynamic-security.json
ADMIN_PW="$(cat /run/secrets/mqtt_admin_password)"
if [ "${1:-}" = "init" ]; then
  [ -f "$F" ] || mosquitto_ctrl dynsec init "$F" admin "$ADMIN_PW"
  chown mosquitto:mosquitto "$F" 2>/dev/null || true
  exit 0
fi
i=0
until mosquitto_ctrl -u admin -P "$ADMIN_PW" --cafile /mosquitto/certs/ca.crt -h mosquitto -p 8884 dynsec listRoles >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "broker not reachable" >&2; exit 1; }; sleep 1
done
c() { mosquitto_ctrl -u admin -P "$ADMIN_PW" --cafile /mosquitto/certs/ca.crt -h mosquitto -p 8884 dynsec "$@" || true; }
c createRole dak-service
for acl in "subscribePattern devices/+/readings" "subscribePattern internal/#" "publishClientSend internal/#" "publishClientSend grants/#" \
           "publishClientSend \$CONTROL/dynamic-security/#" "subscribePattern \$CONTROL/dynamic-security/#"; do
  # shellcheck disable=SC2086
  c addRoleACL dak-service $acl allow 1
done
c createClient dak-service -p "$(cat /run/secrets/mqtt_service_password)"
c addClientRole dak-service dak-service 1
echo "MQTT service role provisioned"
