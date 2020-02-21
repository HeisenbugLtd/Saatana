#!/usr/bin/env bash

trap 'echo "ERROR at line ${LINENO} (code: $?)" >&2' ERR
trap 'echo "Interrupted" >&2 ; exit 1' INT

set -o errexit
set -o nounset

# Expect the repository (including credentials) as first and only argument
if [ $# -ne 1 ]; then
  echo "Missing repository argument!"
  exit 1
fi

timestamp=`date --iso-8601=minutes`
files="artifacts/test*.out"
for file in ${files}
do
  echo ${file}
  printf "\nTest run from ${timestamp}.\n" >> ${file} # add timestamp to force changes
done;
git config --local user.email "gh+saatana@heisenbug.eu"
git config --local user.name "Auto Committer"
git add artifacts
git commit -m "* (Autocommit) Test results."
git push "${1}"
