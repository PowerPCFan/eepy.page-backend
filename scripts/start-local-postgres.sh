#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="eepy-page-postgres-local"
VOLUME_NAME="eepy-page-postgres-local-data"
HOST_PORT="5433"
IMAGE="postgres:17"
PG_USER="postgres"
PG_PASSWORD="postgres"
PG_DB="eepy_page_dev"

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required but was not found on PATH." >&2
    exit 1
fi

existing_container="$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")"

if [ -n "$existing_container" ]; then
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME")" = "true" ]; then
        echo "PostgreSQL container '${CONTAINER_NAME}' is already running."
    else
        echo "Starting existing PostgreSQL container '${CONTAINER_NAME}'..."
        docker start "$CONTAINER_NAME" >/dev/null
    fi
else
    echo "Creating PostgreSQL container '${CONTAINER_NAME}'..."
    docker volume create "$VOLUME_NAME" >/dev/null
    docker run \
        --detach \
        --name "$CONTAINER_NAME" \
        --publish "127.0.0.1:${HOST_PORT}:5432" \
        --env "POSTGRES_USER=${PG_USER}" \
        --env "POSTGRES_PASSWORD=${PG_PASSWORD}" \
        --env "POSTGRES_DB=${PG_DB}" \
        --volume "${VOLUME_NAME}:/var/lib/postgresql/data" \
        "$IMAGE" >/dev/null
fi

echo
echo "PostgreSQL is up! Use this in your dev .env:"
echo "  POSTGRES_URL=\"postgresql://${PG_USER}:${PG_PASSWORD}@localhost:${HOST_PORT}/${PG_DB}\""
