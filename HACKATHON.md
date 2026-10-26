# Munix × Meta Global AI Developer Hackathon 2026

Indie track. Build window **Mon Oct 26 → Wed Nov 4, 9:00 PM ET**. Judging Nov 4–8, live finals Nov 9.

## Rules that shape this repo

- **New work only.** Everything here is written between Oct 26 and Nov 4. The design (`docs/design-spec.md`) was
  written before the event for a private prototype; it guides the build, and no prototype code is used. See the
  clean-room rule in `CLAUDE.md`.
- **Demo only what we built.** Every part shown in the video comes from this repo's history. Web Speed OSS, the
  author's own open-source project, is a disclosed dependency, not part of the submission.
- **Public repo, Meta models.** Judging: Impact 30%, Use of Meta AI tooling 25%, Demo 25%, Technical depth 20%. Every
  model in judged runs is a Meta model (Muse Spark): the demo agent, the planner, the reviewer and the Readers.

## The demo

Two laptops, the same Muse Spark agent (`demo/agent`), the same prompt, the same web access through Web Speed OSS.
The demo site is the mock PixelMart page at `http://pixelmart.test:8080` (`127.0.0.1 pixelmart.test` in `/etc/hosts`).

**What the red-team showed (Oct 26, `docs/redteam/bare-agent.md`):** on its own, Muse Spark resisted all ten injection
techniques in 30 runs: none hijacked, none tainted, one run stalled. So the demo does not stage a model failure.
It opens on that result and makes the case for Munix in three steps that don't depend on the model failing:

1. **Muse Spark is good at this.** Both sides read the poisoned page and both refuse. Show the red-team table.
2. **Assume the takeover anyway.** A model's refusal is a probability: tomorrow's payload, a jailbreak, a swapped
   model or a compromised tool can still take an agent over. Both sides run the agent with a **simulated takeover**
   (labeled on screen). The left emails the attacker. On the right the Gate denies it by code, because the recipient
   traces to a user review rather than the boss's contact. Recovery restarts a clean agent without that review, and the
   boss gets the summary.
3. **Proof and resilience.** The ledger shows why the call was denied. A model's refusal leaves nothing to audit. The
   watchdog ends a stalled agent like the one the red-team found.

The simulated takeover is a demo-agent switch that makes the agent obey instructions in tool results. It is shown as
a simulation, never as the model failing.

## Scope

| Crate / dir | What | Day |
| :-- | :-- | :-- |
| `munix-core` | Validators, labels, trust and bands, manifests, plans, requests, decisions, signing | 1 |
| `munix-ledger` | Hash-chained JSONL audit log | 1 |
| `munix-adapters` | `ModelAdapter` + Meta Model API backend (Muse Spark) + mock | 1 |
| `fixtures/mock-web`, `scripts/` | The poisoned PixelMart page; Meta API smoke test | 1 |
| `munix-gate` | Request validation, refs, Stage-1 policy (destinations trace to the plan's sources), tool proxy, labeling, bands | 2 |
| `munix-tools` | `web.open` via Web Speed OSS, `email.send` to Mailpit | 2–3 |
| `munix-runtime` | `munix run`: agent in a network-less container, MCP channel, model gateway | 3–4 |
| `demo/agent` takeover switch | Simulated takeover for the demo, labeled on screen; checked live against Muse Spark | 4 |
| `scripts/redteam_bare.py` | Ten injection variants against the unprotected agent; results in `docs/redteam/` | 1 (done) |
| `munix-supervisor` | Muse Spark planner, redacted metadata view, gray-zone reviewer | 5 |
| Recovery + watchdog | Kill, quarantine the traced region, restart; liveness, deadlines, spin budget | 6 |
| Integrity Seal / Readers | Whichever is further along; the other is stretch | 7 |

## Schedule

| Day | Date | Done when |
| :-- | :-- | :-- |
| 1 | Mon 10/26 | Core, ledger, Meta adapter and mock site build and test green; live Muse Spark call works once the key lands |
| 2 | Tue 10/27 | The Gate denies the injected email by code and allows the boss's, with a hand-written plan; ledger verifies |
| 3 | Wed 10/28 | Real tools behind the Gate; left side pwned end to end in Mailpit |
| 4 | Thu 10/29 | **MVP:** both sides, same agent and prompt; the right runs under `munix run`. Backup video |
| 5 | Fri 10/30 | Muse Spark writes the signed plan and reviews gray calls from the redacted view |
| 6 | Sat 10/31 | Recovery and watchdog: the boss gets the summary with no human step |
| 7 | Sun 11/1 | Seal or Readers |
| 8 | Mon 11/2 | Red-team and metrics. **Feature freeze** |
| 9 | Tue 11/3 | Video, README, writeup |
| 10 | Wed 11/4 | Buffer. **Submit by noon ET** (deadline 9 PM ET) |

**Cut order if behind:** stretch items → red-team breadth → Readers/seal → watchdog spin budget. **Never cut:** both
sides working, containment (no network, no keys in the agent), Muse Spark as agent, planner and reviewer, the video.

## How we build

The lead session plans, writes contracts and reviews. Scoped builder agents write the code in waves: each owns
listed files only, works against fixed public signatures, and reports briefly. Every wave ends with a review of the
security-relevant code, all checks green, and a commit.
