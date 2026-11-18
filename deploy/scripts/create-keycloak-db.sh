#!/bin/sh
# Postgres init hook: a separate database for Keycloak in the same server.
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "CREATE DATABASE keycloak OWNER $POSTGRES_USER"
