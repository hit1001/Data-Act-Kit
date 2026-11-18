#!/bin/sh
# Builds DATABASE_URL from the Docker secret, then runs the service command.
set -eu
DATABASE_URL="postgres://dak:$(cat /run/secrets/db_password)@db:5432/dak"
export DATABASE_URL
exec "$@"
