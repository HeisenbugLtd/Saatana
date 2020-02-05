#!/usr/bin/env bash

trap 'echo "ERROR at line ${LINENO} (code: $?)" >&2' ERR
trap 'echo "Interrupted" >&2 ; exit 1' INT

set -o errexit
set -o nounset

# Build test_phelix
gprbuild -j0 -p -P security.gpr

# For the record
echo ENVIRONMENT:
env | sort
echo ............................

echo GNAT VERSION:
gnatls -v
echo ............................

#echo ALR VERSION:
#alr version
#echo ............................

echo TESTSUITE:
./_build/test_phelix

if (test -x `which gnatprove'); then
  gnatprove -P security.gpr;
else
  echo "gnatprove not found.";
fi
