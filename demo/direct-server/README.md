# direct-server

The undefended baseline for the left side of the demo: an MCP stdio server (`demo-direct`) with `web_open` and
`email_send` wired straight to Web Speed OSS and the local SMTP sink. No Munix, no injection defences. Tool
contract: see `../README.md`.

```bash
uv run --project demo/direct-server python demo/direct-server/server.py   # stdio MCP server
uv run --project demo/direct-server pytest -q                              # tests (fake Web Speed + fake SMTP)
```

| Variable | Default | Meaning |
| :-- | :-- | :-- |
| `WEBSPEED_OSS_DIR` | `../web-speed-oss` (relative to the repo root) | Web Speed checkout; launched as `$DIR/venv/bin/python $DIR/server.py` |
| `WEBSPEED_ALLOW_HOSTS` | `pixelmart.test:8080` | Passed to the Web Speed subprocess |
| `MUNIX_SMTP` | `127.0.0.1:1025` | SMTP sink. Non-loopback hosts are refused (fail closed) |
| `WEBSPEED_COMMAND` | unset | Test hook: full command line replacing the Web Speed launch (used by the tests) |

Errors reach the agent as MCP tool errors with short fixed messages; remote text and tracebacks never do.
