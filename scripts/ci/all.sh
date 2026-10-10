#!/usr/bin/env bash
# Everything CI runs, locally: the gate, then the server and the three
# smokes against it, each on a fresh state (the same vault and account
# names). Needs go, az, node, terraform and azurite-blob on
# PATH, port 8443 free, and the hostnames of scripts/ci/hosts.sh
# resolving. The server's log is printed when a smoke fails.
set -euo pipefail
cd "$(dirname "$0")/../.."
export CI_DIR="${CI_DIR:-/tmp/armite-ci}"
echo "=== gate"
test -z "$(gofmt -l ./cmd ./internal)" || { gofmt -l ./cmd ./internal; exit 1; }
go vet ./...
go test -race -count=1 ./...
echo "=== server"
rm -rf "$CI_DIR"
./scripts/ci/server.sh start
trap './scripts/ci/server.sh stop; [ "$status" = 0 ] || tail -40 "$CI_DIR/server.log"' EXIT
status=1
./scripts/ci/az-smoke.sh
./scripts/ci/server.sh reset
./scripts/ci/node-smoke.sh
./scripts/ci/server.sh reset
./scripts/ci/terraform-smoke.sh
status=0
echo "=== all green"
