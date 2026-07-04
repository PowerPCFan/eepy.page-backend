#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="eepy-page-mongodb-local"
VOLUME_NAME="eepy-page-mongodb-local-data"
HOST_PORT="27018"  # use 27018 to avoid conflicts, Local GitHub Actions seems to leave a container open on 27017
IMAGE="mongo:8.0"

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required but was not found on PATH." >&2
    exit 1
fi

existing_container="$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")"

if [ -n "$existing_container" ]; then
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME")" = "true" ]; then
        echo "MongoDB container '${CONTAINER_NAME}' is already running."
    else
        echo "Starting existing MongoDB container '${CONTAINER_NAME}'..."
        docker start "$CONTAINER_NAME" >/dev/null
    fi
else
    echo "Creating MongoDB container '${CONTAINER_NAME}'..."
    docker volume create "$VOLUME_NAME" >/dev/null
    docker run \
        --detach \
        --name "$CONTAINER_NAME" \
        --publish "127.0.0.1:${HOST_PORT}:27017" \
        --volume "${VOLUME_NAME}:/data/db" \
        "$IMAGE" >/dev/null
fi

echo
echo "MongoDB is up! Use this in your dev .env:"
echo "  MONGODB_URL=\"mongodb://localhost:${HOST_PORT}/eepy-page-dev\""
