#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${IMAGE:-pact-refd:dev}"

cd "$repo_root"
docker build -f deploy/docker/Dockerfile -t "$image" .
