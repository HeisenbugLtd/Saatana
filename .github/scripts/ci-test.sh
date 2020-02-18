#!/usr/bin/env bash

trap 'echo "ERROR at line ${LINENO} (code: $?)" >&2' ERR
trap 'echo "Interrupted" >&2 ; exit 1' INT

set -o errexit
set -o nounset

echo "Running KAT:"
# Pipe KAT output into file
./_build/test_phelix | tee kat.out

# The test program outputs either <OK> or <FAILED> at the end.
# Use exit status of grep to see if the output contains the expected <OK>
grep "<OK>" kat.out > /dev/null
