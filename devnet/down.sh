#!/usr/bin/env bash
# Stops the devnet and removes its network. Generated keys are kept.
set -euo pipefail

cd "$(dirname "$0")"
engine=${CONTAINER_ENGINE:-podman}

"$engine" compose down --volumes
"$engine" network rm idmx-devnet >/dev/null 2>&1 || true
