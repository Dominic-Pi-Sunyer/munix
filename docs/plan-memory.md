# Plan memory

**Status (Oct 28, 2026): built, offline-tested, not yet measured on a paid run.**
- **Code:** `munix-supervisor::memory`, `munix bridge --plan-memory <dir>`, `MUNIX_PLAN_MEMORY=<dir>` for
  `munix run`, `munix plans`, and `run.py --plan-memory`.
- **Beyond the design:** a reused plan must also pass the planner's own checks (`planner::check_plan`: step, budget
  and amendment limits, store paths), so a hand-edited template can't carry more than the planner would sign.

**Goal:** cut Munix's planner cost on repeated kinds of tasks without moving any security decision to a model.

- **The planner is almost all of the overhead:** about $0.015 of the ~$0.040 a banking task costs under Munix, against
  $0.021 bare.
- **Plan memory reuses an earlier plan** when a new prompt is the same, or the same with its values swapped.

Owner's decisions (Oct 27, 2026):
- **Store policy:** keep plans from clean runs only.
- **Matching:** exact, plus shape (values masked).
- **Order:** build this before plan-on-first-write.

## Why reuse is safe

- **A plan holds no values.** It has ids, the prompt's hash, the readable regions, and steps (a tool, a budget, and
  per-argument rules: `from` source paths, `min_trust`, `dlp`, `may_embed`, `forbid`). No recipient, amount or text
  from the prompt appears in it.
- **The planner sees only clean inputs:** the prompt text, the catalog, and the store *key names*, never the values
  (invariant 3). It never sees what the agent read. A plan therefore depends only on (prompt, catalog, store keys,
  planner version), and reusing it for an equivalent prompt gives the Gate the same rules a fresh planner call would.
- **The Gate still checks every call in code.** Reuse changes where the rules came from, not how they're enforced.

## What is stored

A **template** is the plan without its per-task fields (`plan`, `task`, `prompt_hash`), plus:
- `key`: the exact key and the shape key (below);
- `catalog_digest` and `planner_version` (model, effort, planner prompt digest), so a template dies when either
  changes;
- `summary`: tools and argument sources only ("email.send: to from prompt; cc forbidden"), for review;
- `created`, `uses`.

**No prompt text is stored,** only hashes, since prompts can be personal.

## Matching (deterministic, no model)

1. **Exact:** sha256 of (normalized prompt text, catalog digest, sorted store keys, planner version). Normalizing
   means collapsing whitespace and lowercasing.
2. **Shape:** the same, after masking every token core's validators recognize as a typed value:
   - URL, email, IBAN, phone number, date, number or amount;
   - each is replaced by `<url>`, `<email>`, and so on.

   Masking replaces typed values only, never words. "Write Bob" vs "write Alice" don't match, and the planner runs.

**A miss costs money, never safety.** Masks must come from `munix_core::validate` (no parallel validators,
`CLAUDE.md`).

## Flow

- **At task start, with memory on:** look up exact, then shape.
  - **Hit:** fill in the new plan id, task and prompt hash, `validate` against today's catalog, sign as a plan (as
    `--plan` does), and log `plan_reused {template, level: exact|shape}`. No planner call.
  - **Miss:** the planner runs as today.
- **When the task ends, remember the plan** (`plan_remembered {template}`) only if all of these hold:
  - the plan came from the planner, not a given or reused one;
  - the task had no takeover;
  - no request was denied `off_plan`.

  Writing happens after the task, never during it: the memory directory is an Integrity Seal root while tasks run
  (invariant 11).
- **Managing templates:** `munix plans` lists them (id, summary, uses, created), and `munix plans forget <id>`
  deletes one.

## Interfaces (to be fixed as contracts before building)

- `munix-supervisor::memory`:
  - `PlanMemory::open(dir, catalog, planner_version)`;
  - `lookup(prompt, stores) -> Option<(Template, Level)>`;
  - `remember(plan, prompt, stores)`;
  - `instantiate(template, task, plan_id, prompt_hash) -> Plan`;
  - `prompt_shape(text) -> String`.
- **`munix run`:** `MUNIX_PLAN_MEMORY=<dir>` (off when unset).
- **The bridge:** `--plan-memory <dir>`.
- **`run.py`:** `--plan-memory`.
- **The ledger:** the two new events above. No change to the plan wire type.

## Risks

| Risk | Guard |
| :-- | :-- |
| A bad plan reused forever (missing steps, too many reads) | Clean runs only; `munix plans forget` |
| Shape masking changes meaning | Typed values only; a different count of values or different words is a different shape |
| A tampered template | Sealed during tasks; validated against the catalog on load; its digest logged on each reuse |
| Stale after a tool or planner change | Keyed by the catalog digest and planner version |
| Privacy | Hashes and a tools-and-sources summary only |
| Benchmark honesty | Reported as its own setup ("with plan memory"), with planner calls counted |

## Tests and measurement

- **Offline:**
  - masking for each value type, and for prompts with different words;
  - key derivation;
  - remember-then-lookup at both levels;
  - no hit after a catalog or planner change;
  - nothing remembered after a takeover or an `off_plan` denial;
  - a reused plan equal to the original except its ids;
  - no prompt text on disk;
  - the memory directory sealed during a task;
  - the ledger events.
- **Paid (needs the owner's OK):** the AgentDojo utility then attack phase with memory on. The expected result is
  attack-phase planner calls dropping from 144 to 16 with unchanged ASR and utility. Compare planner calls, cost,
  ASR and utility against the current results.
