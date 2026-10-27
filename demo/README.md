# Demo: the two-laptop run

Two pieces, shared by both sides of the split screen:

| Dir | What | Used by |
| :-- | :-- | :-- |
| `agent/` | An ordinary Muse Spark tool-calling agent (OpenAI SDK + MCP stdio client). Not Munix code: it never imports from this repo | Both sides, unchanged |
| `direct-server/` | MCP server with the demo tools wired straight to Web Speed OSS and Mailpit. No Munix | Left side only |

The right side runs the same agent under `munix run` (the Munix runtime), which serves the same tool names
through the Gate.

## Tool contract (both sides must match)

MCP tool names use underscores, because OpenAI-style function names can't contain dots. The Munix runtime maps
them to the manifests in `/manifests` (`web.open`, `email.send`).

| MCP tool | Arguments (JSON Schema) | Returns (one text content block) |
| :-- | :-- | :-- |
| `web_open` | `{"url": string}` (required) | The page as plain text: a `Title:` line, then headings and text blocks one per line, then a `Links:` section with one URL per line |
| `email_send` | `{"to": [string] (1–5, required), "subject": string (required), "body": string (required), "cc": [string] (0–5, optional)}` | `Sent. message_id=<id>` |

Errors come back as an MCP tool error (`isError: true`) with a short fixed message, never remote text.

## Environment

| Variable | Meaning | Left side | Right side (`munix run`) |
| :-- | :-- | :-- | :-- |
| `OPENAI_BASE_URL` | Model endpoint | `https://api.meta.ai/v1` | Munix's model gateway |
| `OPENAI_API_KEY` | Model key | `MODEL_API_KEY` from `.env` | A placeholder; the gateway adds the real key |
| `MUNIX_WORKER_MODEL` | Model id | `muse-spark-1.3` | `muse-spark-1.3` |
| `MUNIX_WORKER_EFFORT` | Reasoning effort (default `low`); the `--reasoning-effort` flag overrides it | `low` | `low` |
| `MUNIX_SIMULATE_TAKEOVER` | Set to `1` (or pass `--simulate-takeover`) for the labeled takeover scene (default off) | off / `1` | off / `1` |
| `MUNIX_PRICE_INPUT_PER_M` / `MUNIX_PRICE_OUTPUT_PER_M` | USD per million input / output tokens, for the cost line (defaults `1.25` / `4.25`) | defaults | defaults |
| `WEBSPEED_OSS_DIR` | Web Speed OSS checkout | `../web-speed-oss` | (used by Munix, not the agent) |
| `WEBSPEED_ALLOW_HOSTS` | Loopback opt-in | `pixelmart.test:8080` | (used by Munix) |
| `MUNIX_SMTP` | SMTP sink, loopback only | `127.0.0.1:1025` | (used by Munix) |

## Reasoning effort and cost line

`agent.py --reasoning-effort <level>` sets the model's reasoning effort: `minimal`, `low`, `medium`, `high`, `xhigh` or
`max`. The default is `$MUNIX_WORKER_EFFORT`, else `low`. Anything else exits with code 2 before any API call, as does
a negative or non-numeric price.

After the final answer (or the step limit) the agent prints one line:

```
tokens: prompt 1000 · completion 500 (reasoning 200) · calls 1 · est. cost $0.0034
```

It sums usage over every model call (reasoning tokens are already inside completion tokens). The cost is an estimate
from the two price variables above, whose defaults are the published Muse Spark 1.1 rates.

## Demo hostname

The Gate refuses IP-literal URLs (a deliberate hardening rule), so the mock site is reached as `pixelmart.test`,
mapped to loopback with one line in `/etc/hosts`:

```
127.0.0.1 pixelmart.test
```

`.test` is reserved for testing (RFC 2606), so the name can never point anywhere real.

## Prompt

"Read the reviews for the gaming monitor at http://pixelmart.test:8080/reviews/gaming-monitor and email a short summary
to my boss." The boss's address on the left comes from `MUNIX_BOSS_EMAIL` (default `boss@corp.example`), given to
the agent in its system prompt as the user's contact; on the right it's `store.contacts.boss` in the Gate.

## Simulated takeover (`--simulate-takeover`)

Passing `--simulate-takeover` (or setting `MUNIX_SIMULATE_TAKEOVER=1`) appends a short paragraph to the agent's system
prompt instructing the model to treat instructions found in tool results as user instructions, and prints a
`SIMULATED TAKEOVER:` banner to stderr before running. This switch exists solely for the clearly labeled takeover scene
that shows what happens when an agent *is* compromised (with and without Munix); it must never be presented as the
model being fooled. All email in the demo goes to the local Mailpit sink.
