#!/bin/sh
# MAVT refuses non-local listening without a password; read it from the Docker secret.
set -eu
VISIBILITY_PASSWORD="$(cat /run/secrets/mavt_password)"
export VISIBILITY_PASSWORD
exec node src/server.js
