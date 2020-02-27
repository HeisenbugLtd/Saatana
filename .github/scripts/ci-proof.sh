#!/usr/bin/env bash

trap 'echo "ERROR at line ${LINENO} (code: $?)" >&2' ERR
trap 'echo "Interrupted" >&2 ; exit 1' INT

set -o errexit
set -o nounset

echo "Checking provers..."

SPARKDIR=/opt/gnat/libexec/spark/bin

(test -x ${SPARKDIR}/alt-ergo && echo `${SPARKDIR}/alt-ergo -version`) || true
(test -x ${SPARKDIR}/cvc4 && echo `${SPARKDIR}/cvc4 --version`) || true
(test -x ${SPARKDIR}/z3 && echo `${SPARKDIR}/z3 -version`) || true

gnatprove --assumptions --output-header -U -P saatana.gpr | tee gnatprove.stdout
