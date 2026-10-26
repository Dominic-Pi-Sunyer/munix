#!/usr/bin/env bash
# Smoke test for the Meta Model API: one plain chat completion and one strict structured-output completion.
# Run from anywhere once a key is available. Needs MODEL_API_KEY (environment or .env at the repo root).
# Prints the HTTP status and response body of each call. Never prints the key.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ -z "${MODEL_API_KEY:-}" ]]; then
  echo "error: MODEL_API_KEY is not set. Put it in .env (see .env.example) or export it." >&2
  exit 1
fi

BASE_URL="${MUNIX_META_URL:-https://api.meta.ai/v1}"
BASE_URL="${BASE_URL%/}"
MODEL="${MUNIX_SUPERVISOR_MODEL:-muse-spark-1.3}"
URL="${BASE_URL}/chat/completions"

call() {
  local label="$1" payload="$2" out status
  out="$(mktemp)"
  echo "== ${label}: POST ${URL} (model ${MODEL})"
  # The key travels in a header read from stdin-fed config, so it never appears in the process list.
  status="$(printf 'header = "Authorization: Bearer %s"\n' "${MODEL_API_KEY}" |
    curl -sS -o "${out}" -w '%{http_code}' --max-time 60 --config - \
      -H 'Content-Type: application/json' -d "${payload}" "${URL}")" || {
    rm -f "${out}"
    echo "error: request failed (network or TLS problem)" >&2
    return 1
  }
  echo "HTTP ${status}"
  cat "${out}"
  echo
  rm -f "${out}"
  [[ "${status}" == 2* ]]
}

plain=$(
  cat <<JSON
{"model":"${MODEL}","messages":[{"role":"user","content":"Reply with the word ok."}],"max_tokens":256}
JSON
)

structured=$(
  cat <<JSON
{"model":"${MODEL}",
 "messages":[{"role":"user","content":"A user asked to email a summary to their boss. Return your verdict."}],
 "max_tokens":1024,
 "response_format":{"type":"json_schema","json_schema":{"name":"verdict","strict":true,"schema":{
   "type":"object",
   "properties":{"decision":{"type":"string","enum":["approve","deny","confirm_user"]}},
   "required":["decision"],
   "additionalProperties":false}}}}
JSON
)

rc=0
call "plain" "${plain}" || rc=1
call "structured output" "${structured}" || rc=1

if [[ "${rc}" -eq 0 ]]; then
  echo "Both calls succeeded."
else
  echo "At least one call failed." >&2
fi
exit "${rc}"
