#!/usr/bin/env bash
# Starts what both sides of the demo need, if it isn't already running: the Mailpit sink (SMTP 127.0.0.1:1025,
# inbox at http://127.0.0.1:8025) and the mock PixelMart site (http://pixelmart.test:8080). Logs go to runs/.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p runs

if ! grep -q 'pixelmart.test' /etc/hosts; then
  echo "error: add '127.0.0.1 pixelmart.test' to /etc/hosts first" >&2
  exit 1
fi

if curl -sf http://127.0.0.1:8025/api/v1/info >/dev/null 2>&1; then
  echo "Mailpit: already running"
else
  nohup mailpit --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025 >runs/mailpit.log 2>&1 &
  echo "Mailpit: started"
fi

if curl -sf http://pixelmart.test:8080/healthz >/dev/null 2>&1; then
  echo "Mock site: already running"
else
  nohup fixtures/mock-web/start.sh >runs/mock-web.log 2>&1 &
  echo "Mock site: started"
fi

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:8025/api/v1/info >/dev/null 2>&1 && curl -sf http://pixelmart.test:8080/healthz >/dev/null 2>&1; then
    echo "Ready. Inbox: http://127.0.0.1:8025"
    exit 0
  fi
  sleep 0.25
done
echo "error: services did not come up; see runs/mailpit.log and runs/mock-web.log" >&2
exit 1
