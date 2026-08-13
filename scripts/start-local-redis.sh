#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="eepy-page-redis-local"
VOLUME_NAME="eepy-page-redis-local-data"
HOST_PORT="6379"
IMAGE="redis:8.10-alpine"

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required but was not found on PATH." >&2
    exit 1
fi

existing_container="$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")"

if [ -n "$existing_container" ]; then
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME")" = "true" ]; then
        echo "Redis container '${CONTAINER_NAME}' is already running."
    else
        echo "Starting existing Redis container '${CONTAINER_NAME}'..."
        docker start "$CONTAINER_NAME" >/dev/null
    fi
else
    echo "Creating Redis container '${CONTAINER_NAME}'..."
    docker volume create "$VOLUME_NAME" >/dev/null
    docker run \
        --detach \
        --name "$CONTAINER_NAME" \
        --publish "127.0.0.1:${HOST_PORT}:6379" \
        --volume "${VOLUME_NAME}:/data" \
        "$IMAGE" >/dev/null
fi

echo
echo "Redis is up! Port: ${HOST_PORT}"
