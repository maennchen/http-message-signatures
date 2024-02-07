#!/bin/sh

set -ex

TEST_SUITE_VERSION="dfdf7e43e799c1a95658fd5d934873dcd9099d31"

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
TEST_SUITE_DIR="$SCRIPT_DIR/test-suite"
GENERATOR_BIN="$SCRIPT_DIR/generator.exs"

rm -rf "$TEST_SUITE_DIR"

git clone \
    https://github.com/w3c-ccg/http-signatures-test-suite.git \
    "$TEST_SUITE_DIR" \
    --depth 1

(
    cd "$TEST_SUITE_DIR"
    
    npm install

    echo '{}' \
        | jq \
        --arg generator "$GENERATOR_BIN" \
        '. + {"generator": $generator}' \
        > "$TEST_SUITE_DIR/config.json"
)