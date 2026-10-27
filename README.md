# Munix

**A runtime that keeps AI agents safe from prompt injection without taking them off autopilot.** Built for the
**Meta Global AI Developer Hackathon** (Oct 26 – Nov 4, 2026), indie track, on Muse Spark.

A model's refusal is a probability. Munix is built so that it doesn't matter. The agent runs *inside* Munix and
can only act through the **Gate**: plain code that checks every tool call against a plan signed before the agent
read anything risky. If something on a web page talks the agent into emailing an attacker, the Gate sees that the
address came from that page, not from you, and denies the call in code. No model gets the final say.

## Status: rough draft of every piece, working end to end (Day 1 of 10)

| Piece | What it does |
| :-- | :-- |
| `munix run` | Runs an unmodified agent in a container with no network and no keys. Its only routes out are Munix's MCP channel and a model gateway that holds the key |
| The Gate | Validates every call, traces each destination back to where it came from (your prompt, your contacts, or a web page), and enforces trust bands. Trust only ever goes down as the agent reads riskier content |
| Supervisor (Muse Spark) | Writes and signs the plan, and reviews gray-zone calls from a redacted view that never contains an attacker-written string |
| Readers (Muse Spark) | Read risky content for the agent and return only typed, low-capacity answers (counts, stars, enums), so there's no free text for an injection to ride in |
| Recovery and watchdog | A takeover or a stall kills the agent. Munix withholds exactly the content behind it and restarts a clean agent, at most twice |
| Integrity Seal | Any write to Munix's own code, manifests, plans or config while a task runs stops every task |
| Ledger | Every decision, with its reasons, goes into a hash-chained audit log |

## Results so far

- **Muse Spark is good at this.** Run unprotected against ten injection techniques, three runs each, it followed
  none: 0 of 30 hijacked. See [`docs/redteam/bare-agent.md`](docs/redteam/bare-agent.md).
- **So we assume the takeover anyway.** The demo agent has a labeled *simulated takeover* switch that makes it obey
  instructions in tool results. That stands in for tomorrow's payload, a jailbreak or a weaker model; it is not
  Muse Spark failing. With the switch on, across the same ten variants:

  | Setup | Result |
  | :-- | :-- |
  | No Munix | 8 emailed an attacker; 2 put an attacker link in the boss's email |
  | Munix, agent reads the raw reviews | 0 reached an attacker. The Gate denied each attempt in code, and recovery restarted a clean agent |
  | Munix, reviews read by a Reader | 10 clean summaries to the boss, with no human step |

  See [`docs/redteam/munix.md`](docs/redteam/munix.md).
- **Sandbox escape probe:** 9 of 9 escape attempts blocked: the internet, DNS, host services, other relay ports,
  keys in the environment or in files, writable paths, the Docker socket, and Munix's process.
- **Coverage:** [`docs/redteam/munix-coverage.md`](docs/redteam/munix-coverage.md) maps the design spec's 14
  attack classes to existing tests, gaps included.
- **Next:** [AgentDojo](eval/agentdojo/DESIGN.md) on the banking and Slack suites, bare versus under Munix.

## Try it

You'll need:
- Rust 1.89+;
- Docker (Colima works);
- `uv` and Mailpit;
- [Web Speed OSS](https://github.com/Dominic-Pi-Sunyer/web-speed-oss) checked out next to this repo;
- `127.0.0.1 pixelmart.test` in `/etc/hosts`;
- a Meta Model API key in `.env` (copy [`.env.example`](.env.example); `.env` is gitignored).

```bash
demo/services.sh                                # Mailpit and the mock PixelMart site, both on loopback
demo/left.sh                                    # the agent with no Munix
demo/right.sh                                   # the same agent and prompt under munix run
TAKEOVER=1 demo/left.sh                         # the labeled simulated takeover, unprotected
TAKEOVER=1 demo/right.sh                        # ... and under Munix
PLAN=examples/demo-plan-readers.yaml demo/right.sh   # reviews through a typed Reader
demo/tamper.sh                                  # touch a manifest mid-task: the Integrity Seal stops it
```

All email goes to Mailpit at http://127.0.0.1:8025, never to a real mailbox. The mock site's injection payloads
are test data.

## Layout

| Path | What |
| :-- | :-- |
| `crates/` | The Munix runtime in Rust: `core`, `gate`, `ledger`, `supervisor`, `readers`, `runtime`, `adapters`, `tools`, `cli` |
| `manifests/`, `examples/`, `sites/` | Tool manifests, example plans, the site template for the mock store |
| `demo/agent/` | An ordinary Muse Spark tool-calling agent, run unchanged on both sides of the demo, plus the escape probe |
| `demo/direct-server/` | The unprotected baseline: the same tools, no Munix |
| `fixtures/mock-web/` | The poisoned PixelMart page and its ten injection variants |
| `scripts/` | The red-team runner and an API smoke check |
| `docs/` | The pre-event design spec, red-team results, and the live handoff between coding sessions |
| `eval/agentdojo/` | AgentDojo setup and the bridge design |

## Checks

About 560 Rust tests, plus the Python suites:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
uv run --project demo/agent pytest -q demo/agent/tests
uv run --project demo/direct-server pytest -q demo/direct-server/tests
```

## Built during the event

- **New work only:** everything in this repository's git history was written during the hackathon, starting
  Oct 26, 2026.
- **The design:** [`docs/design-spec.md`](docs/design-spec.md) was written before the event for a private
  prototype. It guided this build, and no prototype code is in this repository.
- **Dependency:** [Web Speed OSS](https://github.com/Dominic-Pi-Sunyer/web-speed-oss), the author's own open-source
  project, is used to read web pages. It isn't part of the submission.
- **Models:** every model Munix runs is a Meta model, Muse Spark: the agent, planner, reviewer and Readers.
- **Coding assistant:** the code was written with Claude Code (Anthropic), as the commits' co-author lines show.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
