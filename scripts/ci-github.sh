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

echo "Checking provers..."

SPARKDIR=/opt/gnat/libexec/spark/bin

(test -x ${SPARKDIR}/alt-ergo && echo `${SPARKDIR}/alt-ergo -version`) || true
(test -x ${SPARKDIR}/cvc4 && echo `${SPARKDIR}/cvc4 --version`) || true
(test -x ${SPARKDIR}/z3 && echo `${SPARKDIR}/z3 -version`) || true
#(which gnatprove && gnatprove -P security.gpr) || true
