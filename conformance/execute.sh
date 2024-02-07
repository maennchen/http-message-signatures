#!/bin/sh

set -ex

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
TEST_SUITE_DIR="$SCRIPT_DIR/test-suite"

if [ ! -d "$TEST_SUITE_DIR" ]; then
  "$SCRIPT_DIR/init.sh"
fi

(cd "$TEST_SUITE_DIR" && npm run test -- "$@")