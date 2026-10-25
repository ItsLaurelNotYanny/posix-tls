#!/usr/bin/env bash
# Project-gate: configure stack checks before use. Checks must not modify source.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
FAST=0
case "${1:-}" in
    "") [ "$#" -eq 0 ] || { echo "ERROR: unexpected arguments" >&2; exit 2; } ;;
    --fast) [ "$#" -eq 1 ] || { echo "ERROR: unexpected arguments" >&2; exit 2; }; FAST=1 ;;
    *) echo "Usage: ./check.sh [--fast]" >&2; exit 2 ;;
esac
MODE=full
[ "$FAST" -eq 0 ] || MODE=fast
umask 077
LOG=$(mktemp "${TMPDIR:-/tmp}/project-gate.XXXXXX")
trap 'echo "ERROR: gate interrupted; log=$LOG" >&2; exit 2' INT TERM
need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: $1; log=$LOG" >&2
        exit 2
    fi
}
COUNT=0
run() {
    local label=$1 status
    shift
    printf '\n--- %s ---\n' "$label" >>"$LOG"
    if "$@" >>"$LOG" 2>&1; then
        COUNT=$((COUNT + 1))
    else
        status=$?
        printf 'FAIL: %s (exit=%s); log=%s\n' "$label" "$status" "$LOG" >&2
        tail -n 60 "$LOG" | { head -c 8000; cat >/dev/null; } >&2
        printf '\n' >&2
        case "$status" in 126|127) exit 2 ;; *) exit 1 ;; esac
    fi
}
# Host gate: public hygiene, pinned dependencies, strict C++03 build, TLS contracts, relocated consumers.
# QNX ARMv7 cross-compile/link is a separate explicit check: scripts/check-native.sh.
[ ! -e .git ] || need git
need python3
need cmake
need bash
need ctest
run "public path and language hygiene" python3 -B scripts/check-public-paths.py
run "scripts Python syntax" python3 -B -c 'import ast,pathlib; [ast.parse(p.read_text(),filename=str(p)) for base in ("scripts","examples") for p in pathlib.Path(base).glob("*.py")]'
run "pinned dependencies" python3 -B scripts/dependencies.py
run "configure" cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Release
run "C++03 build" cmake --build build/host --parallel "${BUILD_JOBS:-4}"
if [ "$FAST" -eq 0 ]; then
    run "TLS and exchange tests" ctest --test-dir build/host --output-on-failure --no-tests=error
    run "host symbol isolation check" python3 -B scripts/check-symbol-isolation.py build/host/posix_tls_probe build/host/test_tls build/host/test_standalone_consumer
    run "relocated installed C/C++ consumers" bash scripts/check-installed-consumer.sh
    need openssl
    run "TCP TLS 1.3 example" python3 -B examples/check-probe.py
fi
# --- custom checks (preserve during refresh) ---
[ "$COUNT" -gt 0 ] || { echo "ERROR: no checks ran; log=$LOG" >&2; exit 2; }
printf 'OK: project-gate (%s, checks=%s)\n' "$MODE" "$COUNT"
rm -f -- "$LOG"
