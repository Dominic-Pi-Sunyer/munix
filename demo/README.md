# Demo: the two-laptop run

Two pieces, shared by both sides of the split screen:

| Dir | What | Used by |
| :-- | :-- | :-- |
| `agent/` | An ordinary Muse Spark tool-calling agent (OpenAI SDK + MCP stdio client). Not Munix code: it never imports from this repo | Both sides, unchanged |
| `direct-server/` | MCP server with the demo tools wired straight to Web Speed OSS and Mailpit. No Munix | Left side only |

The right side runs the same agent under `munix run` (Munix runtime, Day 4), which serves the same tool names
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
| `WEBSPEED_OSS_DIR` | Web Speed OSS checkout | `../web-speed-oss` | (used by Munix, not the agent) |
| `WEBSPEED_ALLOW_HOSTS` | Loopback opt-in | `pixelmart.test:8080` | (used by Munix) |
| `MUNIX_SMTP` | SMTP sink, loopback only | `127.0.0.1:1025` | (used by Munix) |

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
