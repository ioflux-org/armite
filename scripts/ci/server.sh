#!/usr/bin/env bash
# Builds Provisio and runs it in the background for the smoke scripts,
# with a home directory of its own so nothing of the developer's is
# touched: ./scripts/ci/server.sh start | reset | stop. reset restarts
# it on an empty state with the same CA - each smoke creates the same
# vault and storage account, so each gets a fresh one. CI_DIR holds the
# binary, the home and server.log (default: /tmp/provisio-ci).
set -euo pipefail
CI_DIR="${CI_DIR:-/tmp/provisio-ci}"
export PROVISIO_HOME="$CI_DIR/home"

start() {
    mkdir -p "$CI_DIR"
    [ -x "$CI_DIR/provisio" ] || go build -o "$CI_DIR/provisio" ./cmd/provisio
    "$CI_DIR/provisio" >> "$CI_DIR/server.log" 2>&1 &
    echo $! > "$CI_DIR/server.pid"
    for _ in $(seq 1 60); do
        grep -q 'Serving https' "$CI_DIR/server.log" 2>/dev/null && break
        sleep 0.5
    done
    if ! grep -q 'Serving https' "$CI_DIR/server.log"; then
        echo "server did not start:" >&2; cat "$CI_DIR/server.log" >&2; exit 1
    fi
    if grep -q 'Microsoft.Storage disabled' "$CI_DIR/server.log"; then
        echo "azurite-blob is not on PATH: npm install -g azurite" >&2; exit 1
    fi
    echo "serving; CA at $PROVISIO_HOME/ca.pem, log at $CI_DIR/server.log"
}

stop() {
    if [ -f "$CI_DIR/server.pid" ]; then
        kill "$(cat "$CI_DIR/server.pid")" 2>/dev/null || true
        rm -f "$CI_DIR/server.pid"
        sleep 1
    fi
}

case "${1:-}" in
start) start ;;
stop) stop ;;
reset)
    stop
    rm -rf "$PROVISIO_HOME/state"
    : > "$CI_DIR/server.log"
    start
    ;;
*)
    echo "usage: $0 start|reset|stop" >&2; exit 2
    ;;
esac
