#!/usr/bin/env bash

trap 'echo "ERROR at line ${LINENO} (code: $?)" >&2' ERR
trap 'echo "Interrupted" >&2 ; exit 1' INT

set -o errexit
set -o nounset

echo "Running KAT:"
# Pipe KAT output into file
./_build/test_phelix > kat.out
# Test subprogram sets exit status depending on if all tests succeeded or not.
