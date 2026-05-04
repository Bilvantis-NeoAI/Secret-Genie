#!/bin/bash
# Thin wrapper that forwards all arguments to the SecretGenie CLI binary.
# Useful when the binary is not on PATH.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [[ -x "$SCRIPT_DIR/secretgenie" ]]; then
    BIN="$SCRIPT_DIR/secretgenie"
elif [[ -x "$SCRIPT_DIR/secretgenie-hsbc" ]]; then
    BIN="$SCRIPT_DIR/secretgenie-hsbc"
else
    echo "ERROR: secretgenie binary not found alongside this wrapper." >&2
    exit 1
fi

exec "$BIN" "$@"
