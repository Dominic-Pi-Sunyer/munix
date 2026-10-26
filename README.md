# Munix

A runtime that stops prompt injection from steering AI agents, while keeping them on autopilot. Built for the
**Meta Global AI Developer Hackathon** (Oct 26 – Nov 4, 2026), indie track.

The agent runs *inside* Munix. Plain code (the **Gate**) decides what it may do, based on a plan signed before it
read anything risky; a **Supervisor** running Muse Spark plans and reviews from a view with every attacker-written
string redacted; and trust only ever goes down as the agent reads riskier content.

## Built during the event

Everything in this repository's git history was written during the hackathon, starting Oct 26, 2026.

- `docs/design-spec.md` is the design, written before the event for a private prototype. It guided this build; no
  prototype code is in this repository.
- [Web Speed OSS](https://github.com/Dominic-Pi-Sunyer/web-speed-oss) (the author's own open-source project) is used
  as a dependency for reading web pages. It isn't part of the submission.

## Layout

| Path | What |
| :-- | :-- |
| `crates/` | The Munix runtime (Rust) |
| `demo/agent/` | An ordinary Muse Spark tool-calling agent, run unchanged on both sides of the demo |
| `demo/direct-server/` | The unprotected baseline: the same tools, no Munix |
| `docs/design-spec.md` | The pre-event design |
| `HACKATHON.md` | Scope and schedule for the build window |

## Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
uv run --project demo/agent pytest -q demo/agent/tests
uv run --project demo/direct-server pytest -q demo/direct-server/tests
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
