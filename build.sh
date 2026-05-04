#!/bin/bash
set -euo pipefail

echo "Building SecretGenie CLI..."

if [ -f "venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

python -m pip install -r requirements.txt

HSBC_BUILD=false
SPEC="packaging/genie.spec"
NAME="secretgenie"
if [ "${1:-}" = "hsbc" ]; then
    echo "Building HSBC variant..."
    HSBC_BUILD=true
    SPEC="packaging/genie-hsbc.spec"
    NAME="secretgenie-hsbc"
fi

pyinstaller --clean "$SPEC"

if [ "$(uname)" = "Darwin" ] && [ -n "${APPLE_DEVELOPER_ID:-}" ]; then
    echo "Signing $NAME with Developer ID: $APPLE_DEVELOPER_ID"
    codesign --force --options runtime --sign "$APPLE_DEVELOPER_ID" "dist/$NAME"
fi

cp secretgenie-cli.sh "dist/secretgenie-cli.sh" 2>/dev/null || true
chmod +x "dist/secretgenie-cli.sh" 2>/dev/null || true

echo ""
echo "Build complete."
echo "  Binary:  dist/$NAME"
echo "  Wrapper: dist/secretgenie-cli.sh"
if [ "$HSBC_BUILD" = true ]; then
    echo "  Variant: HSBC"
fi
