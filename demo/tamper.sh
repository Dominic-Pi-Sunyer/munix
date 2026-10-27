#!/usr/bin/env bash
# The Integrity Seal scene: run the right side (demo/right.sh), then, while the task runs, write to one of Munix's
# own files. `touch` changes no content, so the repo stays clean, but it is still a write: the seal trips, every
# task stops, and nothing recovers.
#
#   demo/tamper.sh                     # touches manifests/email.send.yaml after 10 s
#   TAMPER_AFTER=20 TAMPER_FILE=examples/demo-plan.yaml PLAN=examples/demo-plan.yaml demo/tamper.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

after="${TAMPER_AFTER:-10}"
file="${TAMPER_FILE:-manifests/email.send.yaml}"

# Build first, so the delay counts from the seal being taken rather than from compiling.
cargo build -q -p munix-cli
demo/right.sh "$@" &
run=$!
sleep "$after"
echo "tamper.sh: writing to $file" >&2
touch "$file"
wait "$run"
