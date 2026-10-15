#!/usr/bin/env bash
# Builds Armite and runs it in the background for the smoke scripts,
# with a home directory of its own so nothing of the developer's is
# touched: ./scripts/ci/server.sh start | reset | stop. reset restarts
# it on an empty state with the same CA - each smoke creates the same
# vault and storage account, so each gets a fresh one. CI_DIR holds the
# binary, the home and server.log (default: /tmp/armite-ci).
set -euo pipefail
CI_DIR="${CI_DIR:-/tmp/armite-ci}"
export ARMITE_HOME="$CI_DIR/home"
BIN="$CI_DIR/armite"
case "$(uname -s)" in
MINGW*|MSYS*|CYGWIN*) BIN="$BIN.exe"; windows=1 ;;
*) windows= ;;
esac

start() {
    mkdir -p "$CI_DIR"
    [ -x "$BIN" ] || go build -o "$BIN" ./cmd/armite
    "$BIN" >> "$CI_DIR/server.log" 2>&1 &
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
    echo "serving; CA at $ARMITE_HOME/ca.pem, log at $CI_DIR/server.log"
}

stop() {
    if [ -n "$windows" ]; then
        # Windows has no signals: taskkill ends the process and, with
        # //T, the tree under it. Doubled slashes keep Git Bash from
        # rewriting /F into a path.
        taskkill //F //T //IM armite.exe >/dev/null 2>&1 || true
    elif [ -f "$CI_DIR/server.pid" ]; then
        pid=$(cat "$CI_DIR/server.pid")
        kill "$pid" 2>/dev/null || true
        # SIGTERM is a clean stop: in-flight requests finish, Azurite is
        # ended politely, the journal closed. Wait for it, up to 6 s.
        for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
    fi
    rm -f "$CI_DIR/server.pid"
}

case "${1:-}" in
start) start ;;
stop) stop ;;
reset)
    stop
    rm -rf "$ARMITE_HOME/state"
    : > "$CI_DIR/server.log"
    start
    ;;
*)
    echo "usage: $0 start|reset|stop" >&2; exit 2
    ;;
esac
