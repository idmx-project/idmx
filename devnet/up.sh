#!/usr/bin/env bash
# Builds the image, creates the network, and starts the devnet.
# Uses podman (rootless) by default; CONTAINER_ENGINE=docker also works.
set -euo pipefail

cd "$(dirname "$0")"
engine=${CONTAINER_ENGINE:-podman}

./setup.sh
"$engine" build -t localhost/idmx-devnet:latest -f Containerfile ..

if ! "$engine" network inspect idmx-devnet >/dev/null 2>&1; then
    if [[ $engine == podman ]]; then
        "$engine" network create --disable-dns --subnet 10.89.53.0/24 idmx-devnet
    else
        "$engine" network create --subnet 10.89.53.0/24 idmx-devnet
    fi
fi
"$engine" compose up -d --force-recreate
