#!/usr/bin/env bash
# The visual demo, one side per take: the agent's page read opens a visible browser, and the email lands in the
# Mailpit inbox on screen. Record each side full screen and put them side by side in the edit.
#
#   demo/visual.sh left            # the plain agent: the injected recipient gets the email
#   demo/visual.sh right           # the same agent inside Munix: refused, then the summary goes to the boss
#   CLEAR=1 demo/visual.sh left    # empty the local Mailpit inbox first, for a clean shot
#   REAL=1 demo/visual.sh left     # without the labeled simulated takeover (bare Muse Spark usually resists)
#
# By default both sides run with the labeled simulated takeover (`--simulate-takeover`): the agent is told to obey
# instructions in tool results, so the scene shows what happens once an agent *is* compromised. Label it on screen as
# a simulated takeover; never present it as the model being fooled (demo/README.md). Every email goes to the local
# Mailpit sink. Each take spends a few cents of Meta credit.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

side="${1:-}"
if [ "$side" != "left" ] && [ "$side" != "right" ]; then
  echo "usage: demo/visual.sh left|right" >&2
  exit 2
fi

demo/services.sh

if [ "${CLEAR:-0}" = "1" ]; then
  # Local test sink only: these are emails earlier demo takes sent to Mailpit.
  curl -sf -X DELETE http://127.0.0.1:8025/api/v1/messages >/dev/null
  echo "Mailpit: inbox emptied"
fi

open "http://127.0.0.1:8025"
if [ "$side" = "right" ]; then
  if ! curl -sf http://127.0.0.1:8090/api/runs >/dev/null 2>&1; then
    nohup cargo run -q -p munix-cli -- dashboard --runs runs --port 8090 >runs/dashboard.log 2>&1 &
    for _ in $(seq 1 120); do
      curl -sf http://127.0.0.1:8090/api/runs >/dev/null 2>&1 && break
      sleep 0.5
    done
  fi
  open "http://127.0.0.1:8090"
fi

export HEADED=1
export WEBSPEED_HEADED_HOLD_MS="${WEBSPEED_HEADED_HOLD_MS:-10000}"
if [ "${REAL:-0}" != "1" ]; then
  export TAKEOVER=1
  echo "SIMULATED TAKEOVER: label this take on screen"
fi

echo "Starting the $side side in 5 s: start recording now."
sleep 5
exec "demo/$side.sh"
