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

The headline is a **real attack, not a staged one.** Muse Spark resisted every public injection we tried, both the
ten PixelMart variants (0 of 30 runs) and AgentDojo's 144 attack cases. So an adaptive attacker (`eval/agentdojo/adaptive.py`)
had Muse Spark write fresh injections against the bare agent. It found two that work: in 6 of 6 replays the bare
agent was taken over, and under Munix 0 of 6. The video is built on that result, in four beats:

1. **The attack works on a strong model.** In AgentDojo's simulated bank, the user asks the agent to adjust their rent
   from the landlord's notice. A stranger's hidden instruction makes the bare agent redirect the user's standing order
   to the attacker's account.
   - Command: `demo_replay.py --case rent --side bare --live`. AgentDojo's own check prints the verdict.
2. **Same agent, same attack, under Munix: blocked in code.** `demo_replay.py --case rent --side munix --live`. The
   Gate denies the redirect because the recipient traces to a stranger's data, not to anything the user gave.
   - The ledger lines show the rule (`recipient.trace_untrusted`), the takeover and the verified hash chain.
   - No model made that call.
3. **How it works: the PixelMart walkthrough.** Two terminals, the same agent and prompt, a web page and an email to
   the boss (`demo/left.sh`, `demo/right.sh`). On screen: the trace line naming where an address came from, refs,
   a Reader turning reviews into typed values, and recovery restarting a clean agent.
   - The labeled simulated takeover appears here only as a stress test ("assume a takeover anyway"), never as the
     model failing.
4. **Proof at scale.** AgentDojo banking (`docs/redteam/agentdojo.md`): 0 of 144 attacks succeeded under Munix, with
   the utility cost shown honestly. Optionally, the Integrity Seal stopping a task when a manifest is touched
   (`demo/tamper.sh`).

**Rules for the video:**
- **The injected text is never shown.** It's a working attack on a production Meta model, so it stays in the gitignored
  `results/private/` until it's reported to Meta (bugbounty.meta.com). `demo_replay.py` shows only tool names,
  recipients, ids and amounts, never free text.
- **Rehearse for free** with `--recorded`. A `--live` take costs about $0.03 bare and $0.06 under Munix, and is
  charged to the credit floor.
- **The `munix dashboard` page is a debugging tool,** not part of the video: a dashboard would read as monitoring,
  while Munix decides in code before a call runs.

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
