#!/usr/bin/env bash

trap 'echo "ERROR at line ${LINENO} (code: $?)" >&2' ERR
trap 'echo "Interrupted" >&2 ; exit 1' INT

set -o errexit
set -o nounset

echo "Running Phelix tests..."
# Pipe KAT output directly into target file
# Test program runs all KATs plus transmission tests by default, but does minimal output by default.
# We want the full test runs, but also text output, so we specify --verbose (but not --kat-only).
./_build/test_phelix --verbose > artifacts/test_phelix.out
# Test subprogram sets exit status depending on if all tests succeeded or not.
