# Munix design spec (pre-event)

> **Written before the hackathon (Oct 7–25, 2026) as the design for a private prototype.** It is the plan this
> repository implements; no code from that prototype is in this repository. Section references to milestones,
> crates and review findings describe the prototype, not this codebase. What was built during the event is
> everything in this repository's git history (first commit Oct 26, 2026).


*v0.3, 2026-10-10. M0–M2 are done (see the roadmap in section 12 and [STATUS.md](docs/STATUS.md) for the current state and next steps). The wire types live in `crates/munix-core`, JSON Schemas in `/schemas`, example manifests in `/manifests`, and the worked example in `/examples`. When this document and the code disagree, the code and schemas are authoritative.*

Munix sits between any AI agent (any model, any framework) and everything the agent can touch: tools, the web, MCP servers, credentials. Its job is to make sure untrusted content can't cause actions the user didn't intend, and can't leak data to places the user didn't intend, while the agent still runs on autopilot.

The enforcement doesn't depend on any model resisting injection. Plain code (the **Gate**) enforces the rules, and a **Supervisor** model that never sees untrusted content plans and approves. **Trust Factor** scores at the level of page regions decide how strict review is. That way the agent isn't either fully trusted or locked down. Its review tightens step by step as it reads riskier content.

---

## 1. Design invariants

These rules are not negotiable. Every component has to preserve them.

1. **Security doesn't depend on any model.** Swapping models changes how useful the agent is, never how safe it is.
2. **The worker can't act on its own.** Agent A holds no credentials and has no direct network access. The Gate is its only path to the world.
3. **The supervisor's model never sees a string an attacker chose.** URLs, domain names, usernames, page titles and content are replaced with reference IDs and metadata.
4. **Trust only goes down.** Within one instance of Agent A, context trust never increases. Neither user approvals, nor Supervisor approvals, nor time passing, nor later clean reads raise it. Only a fresh instance starts at 100.
5. **Unknown means untrusted.** Content that hasn't been classified, sources that haven't been traced, and sites never seen before all default to low trust.
6. **Code decides first.** The LLM reviews only gray-zone requests, and it can never override a deterministic denial.
7. **Detectors can only lower trust.** Heuristic or ML classifiers can push a trust score down but never up.
8. **Everything is logged.** Every read, request, decision and action goes into a tamper-evident ledger along with the reasons for it.
9. **Munix is the runtime; the agent runs inside it.** Munix launches Agent A, owns its only channel to tools and models, and can stop it at any time. The agent never chooses whether to talk to Munix, and ignoring Munix leaves it with no way to act.
10. **A stalled or spinning agent is an attack.** Progress is measured against the signed plan; an agent that stops making progress is killed and replaced, never left running.
11. **Munix's own code is sealed while a task runs.** Any change to what defines Munix's behavior (its binaries, source, manifests, plans, policy, config, or the tools it launches) kills every running task. Nothing resumes until the user starts a fresh instance and re-seals.

---

## 2. Threat model

**Assets:** user credentials, private data, the ability to act (send, pay, post, delete, change files), and the integrity of what the agent reports back.

**What the attacker can do:**
- Control any content Agent A reads: web pages, comments, emails, documents, third-party API responses, outputs from MCP tools.
- Choose the domain names, usernames, page titles and file names that metadata will show.
- Adapt and retry. The attacker knows how Munix works (Kerckhoffs's principle: the design is assumed public).
- Take over an agent that has its own file or shell access on the same machine, and use it to edit Munix's files: make `email.send` tier 0, loosen a plan, or plant code that runs at the next restart or the next tool launch.
- Make a hijacked agent route around Munix: drop its MCP connection, call the network directly, or read keys from the environment.
- Disrupt instead of act: make the agent stall, loop, or burn tokens on meaningless work.

**Out of scope for v1:**
- a malicious user
- a compromised host or a compromised Munix process (an agent that can kill or attach to the Munix process, or write files as Munix's own user, is a host compromise: the Integrity Seal detects file changes but can't stop that; OS isolation can, see section 9)
- a compromised model provider or backdoored model weights
- volume denial-of-service from outside (a flood of tasks or requests; budgets only limit cost). Disruption *through* a hijacked agent is in scope as G6

**What the attacker wants, and what Munix claims:**

| # | Attacker goal | What Munix claims |
|---|---|---|
| G1 | Make the agent take an action the user didn't authorize | Prevented for tier 2–3 tools, under the assumptions below |
| G2 | Get private data out (exfiltration) | Prevented for traceable data. Free text that has been paraphrased or encoded is a known residual risk |
| G3 | Manipulate a decision or the output | Bounded, not prevented. Labels follow data into the output, and lower context trust tightens review |
| G4 | Persist across sessions (poison memory) | Prevented. Memory keeps its labels, and recalling an item counts as reading at that item's trust level |
| G5 | Abuse resources | Bounded by budgets in the plan |
| G6 | Disrupt the work: stall, loop or waste the agent's effort | Bounded, not prevented. The watchdog kills an agent that stops making progress and recovery restarts it; after two restarts the task pauses and the user is told |

**What the claims assume:**
- **Complete mediation:** every tool and every network route goes through the Gate. The Munix runtime provides this by construction: the agent runs sandboxed, with no network and no route but Munix's channel.
- **A sound plan:** the Supervisor's plan reflects what the user actually intended.
- **Destination tracing works:** the Gate can trace destination arguments back to their sources.

---

## 3. Architecture

```
                       ┌───────────── CLEAN SIDE ─────────────┐
 User ──► Ingress ─────┼──► Supervisor (Agent B)              │
          auth, HMAC   │      planner + approver              │
                       │      sees: signed prompt, plan,      │
                       │            metadata view             │
                       │            ▲            │ signed     │
                       │   metadata │            ▼ decisions  │
                       │        ┌──────────────────────┐      │
                       │        │        GATE          │◄─────┼── Vault (credentials)
                       │        │ tool proxy · labeler │      │
                       │        │ tracer · DLP · policy│──────┼──► tools / web / MCP
                       │        │ ledger · filter      │      │
                       │        └──────────────────────┘      │
                       └───────────▲──────────┬───────────────┘
                     typed requests│          │ labeled, filtered results
                       ┌───────────┴──────────▼───────────────┐
 Ingress ──prompt─────►│  Worker (Agent A)    Readers         │
                       │  any model/framework (disposable,    │
                       │  no creds, no net    typed output)   │
                       └───────────── DIRTY SIDE ─────────────┘
```

| Component | Side | What it does |
|---|---|---|
| **Ingress** | Clean | Authenticates the user. Separates instructions from attached or pasted data. Signs the prompt with HMAC (bound to session and nonce) and issues a task ID. |
| **Supervisor (Agent B)** | Clean | **Planner:** turns the prompt into the Plan of Record. **Approver:** rules on each request using the metadata view. Any model, through an adapter. |
| **Runtime** | Clean | `munix run -- <agent command>`. Launches Agent A as a child in a sandbox (a container with no network in v1), owns its MCP channel over stdio and a model gateway, and is the only thing that can start, stop or restart it. Hosts the watchdog. |
| **Worker (Agent A)** | Dirty | The customer's agent, unchanged. It runs inside the runtime; its tools are Munix's MCP channel and its model calls go through Munix's gateway, which adds the API key so A never holds one. |
| **Gate** | Clean | Deterministic core with no LLM inside. Sub-modules are listed below. |
| **Trust Engine** | Clean | Splits pages into regions, classifies them, and scores domains, regions and authors. Its threat data improves over time. |
| **Readers** | Dirty | Disposable sub-agents with no tools. They read risky content and return typed answers too small to carry instructions. |
| **Vault** | Clean | Stores credentials. Only the Tool Proxy can read it; A only ever sees placeholders. |
| **Console** | Clean | The user confirmation screen. The system renders it from metadata plus where each value came from; Agent A never writes it. |
| **Ledger** | Clean | Append-only, hash-chained audit log. |

**Gate sub-modules:**

- **Tool Proxy:** the only component that executes tools. It inserts credentials from the Vault.
- **Request Validator:** checks requests against the schema, resolves reference IDs, and enforces budgets.
- **Ingest Labeler:** labels everything returned to A with its region, author and trust.
- **Content Filter:** removes hidden text, and removes region types the plan doesn't list.
- **Provenance Tracer:** works out where each argument value came from.
- **DLP Scanner:** checks outgoing values for confidential data, including encoded variants. (DLP means data-loss prevention: scanning for secrets or private data leaving.)
- **Policy Engine:** deterministic rules for tiers, roles and strictness bands.
- **Ledger Writer.**
- **Watchdog.** Deterministic progress checks, no LLM. The plan carries limits, from code defaults the planner can only tighten, covered by the plan's signature:
  - *liveness*: no tool or model call for N seconds (default 60);
  - *step and task deadlines*: wall-clock budgets per step and for the whole task;
  - *spin budget*: model calls and tokens (counted at the gateway) since the last completed plan step.

  Tripping any of them is treated as a takeover and goes to recovery (section 6). The watchdog can't make an agent useful; it bounds how long and how expensively it can be stalled.
- **Integrity Seal** (the "rubber stamp"). At task start it hashes everything that defines Munix's behavior and records the seal digest in the ledger:
  - Munix's binaries (the runtime and everything it launches from this repo), `Cargo.toml`, `Cargo.lock` and `crates/**`;
  - `manifests/`, plans, policy and config files, `.env`;
  - the code of tools Munix launches (e.g. Web Speed OSS), since a modified tool runs at its next spawn.

  A file watcher (FSEvents/inotify) reports any write to a sealed path the moment it happens, even if the file is changed back; the Gate also re-verifies the seal before every `execute` as a backstop. On a mismatch, or if the watcher fails or a file can't be hashed (fail closed), the Gate:
  1. kills every running task: refuses pending and new requests and closes the Worker's session;
  2. writes `tamper_detected` (path, old and new digest) to the ledger;
  3. raises a Console alert.

  Resuming needs a fresh Worker instance and a re-seal confirmed by the user at the Console (`Purpose::UserConfirmation`). On restart, the Gate refuses to resume a task whose seal digest no longer matches. The seal *detects* tampering; *preventing* it is OS isolation (section 9).

---

## 4. Data model

### 4.1 Labels

Every region the Gate delivers, and every value derived from one, carries a label (`munix_core::label::Label`, schema `schemas/label.schema.json`):

```json
{
  "source":       {"kind": "web", "domain": 7},
  "region":       "product_listing",
  "author":       {"kind": "operator"},
  "trust":        78,
  "confidential": "public",
  "capacity":     "free_text"
}
```

- `source`: `prompt`, `user_data`, `store`, `web`, `tool`, `memory`, `reader` or `vault`. Web sources carry an opaque domain number, never the domain name.
- `author`: `operator`, `user`, `account` (an opaque author number) or `unknown`.
- `trust`: 0–100. Integrity: how far the content can be believed or acted on.
- `confidential`: `public < internal < private < secret`. Where the content may go.
- `capacity`: `{"typed": {"bits": n}}` or `"free_text"`. How much it could say.

### 4.2 Tool manifest

Every tool is registered with a manifest. Manifests for third-party MCP servers are approved by the operator, then pinned and hashed. If a server's tool description changes later, the tool goes back for review, which defends against a server swapping in a malicious description after approval (a "rug pull"). Unpinned tool descriptions never reach the Supervisor.

The five example manifests are in `/manifests`: `email.send`, `web.search`, `web.open`, `github.get_issue` and `fs.read_file`.

```yaml
tool: email.send
description: Send an email from the user's account to one or more recipients.
tier: 3                      # 0 read-only · 1 egress · 2 write · 3 irreversible
egress: true
credentials: vault://gmail/oauth
args:
  to:          {type: "email[]", role: destination, max: 5}
  cc:          {type: "email[]", role: destination, max: 5, optional: true}
  subject:     {type: text,      role: content,     max_len: 200}
  body:        {type: text,      role: content,     max_len: 20000}
  attachments: {type: "ref[]",   role: content,     max: 10, optional: true}
output:
  message_id:  {type: id, region: operator_content}
```

- **Types:** `text`, `email`, `url`, `phone`, `id`, `ref`, `bool`, `int`, `number`, `date` and `enum` (with `values`). Add `[]` for a list. For string-shaped types, a Gate-held `ref:` can stand in for the raw value.
- **Output fields** take `region`, an optional `author_field`, and `confidential` (default `public`). For example, `fs.read_file` marks file contents as `user_content` and `private`.
- **Validation:**
  - Tier 0 tools can't have egress.
  - A destination argument can't be a bool, number or date.
  - Unknown fields are rejected.

**Argument roles** decide which checks apply:

| Role | Examples | Main check |
|---|---|---|
| `destination` | to, url, recipient, account, path, phone | **Where it came from.** It must trace to a source that is allowed and trusted enough. |
| `content` | body, query, message, form text | **Confidentiality.** DLP checks that no private data goes to a destination that isn't allowed. |
| `selector` | item ID, choice, index | Must be a reference to something already known. Its label is checked against the plan. |
| `control` | flags, counts, options | Schema and range checks only. |

### 4.3 Plan of Record (PoR)

The Supervisor produces the plan in the planning phase, signs it, and binds it to the prompt's hash. **Everything not in the plan is denied.** The full example is `examples/plan.yaml`, bound to `examples/prompt.json`.

```yaml
plan: P-8f3a
task: T-91c2
prompt_hash: sha256:89460fb8...         # digest of the prompt envelope body
reads: [search_snippet, operator_content, product_listing, editorial, ugc_review]
steps:
  - id: 1
    tool: web.search
    args:
      query: {dlp: no_private}
    budget: 5
  - id: 2
    tool: web.open
    args:
      url: {from: [step.1.results], min_trust: 20}
    budget: 15
  - id: 3
    tool: email.send
    args:
      to:          {from: [store.contacts.boss]}
      cc:          {forbid: true}
      subject:     {dlp: no_secret}
      body:        {dlp: no_secret, may_embed: {from: [step.2], min_trust: 60}}
      attachments: {forbid: true}
    budget: 1
amendments:
  auto_max_tier: 1                      # tier 2-3 steps and new destinations always need the user
```

**Source paths:** `prompt`, `user_data`, `store.<name>[.<key>]`, `step.<n>[.<field>]`.

**Argument rules:**
- `from` lists allowed sources, and `min_trust` sets a trust floor.
- `dlp` is one of `no_secret`, `no_private` or `public_only` (content args only).
- `may_embed` is required before a content arg may embed refs, such as a link in an email body. Without it, embedded refs are denied.
- `forbid` means the argument must be absent.

**Validation rules** (`Plan::validate`):
- Step ids must be unique.
- Budgets run from 1 to 1000.
- Every tool must be in the catalog, and every constrained argument must exist on that tool.
- `step.N` references must point to earlier steps and to output fields that actually exist, so data only flows forward.
- `hidden` is never allowed in `reads`.
- **Every destination argument of a tier 1+ tool needs either `from` or `forbid`.** This is "unknown means untrusted" enforced when the plan is created.

### 4.4 Request (Agent A → Gate)

```json
{"task":"T-91c2","plan":"P-8f3a","step":3,"tool":"email.send",
 "args":{"to":["ref:c1"],"subject":"Monitor pick",
         "body":"Top pick: ref:u4 (4.6 stars across 1,200 reviews)."}}
```

A may pass references or raw strings. References resolve directly, and the Gate traces raw strings back through what A has read.

The first check is `Request::check_shape` against the manifest. It returns coarse violation codes: `tool_mismatch`, `unknown_arg`, `missing_arg`, `wrong_type`, `too_many`, `too_long`, `not_in_enum`. Unknown request fields are rejected, so A can't add a field like `"trust": 100`.

### 4.5 Metadata view (what B's model sees)

```
REQUEST   step 3/3 · email.send (tier 3) · call 1 of max 1
ARG to[0] ref#c1  email  source=contacts:"boss" (named in prompt)   trust=100
ARG body  text 64 chars · embeds ref#u4
          ref#u4  url  source=domain#7/product_listing              trust=78
          dlp=clean · confidential_data=none
CONTEXT   trust=34 · band 20-49 · lowest=domain#12/ugc_review
CHECKS    step ok · tool ok · budget ok · to.source ok · body.url.trust ok (>=60)
```

It contains no raw URLs, no domain names, no usernames and no page text. The Console shows the *user* the real values.

### 4.6 Decision (B → Gate)

```json
{"body": {"verdict":"approve","request_hash":"sha256:...","task":"T-91c2","plan":"P-8f3a",
          "band":"20-49","stage":"llm_review","reasons":["plan.step3","to.source=contacts"]},
 "sig": "hmac-sha256:..."}
```

- **`verdict`:** `approve`, `deny`, `confirm_user` or `require_amendment`.
- **`stage`:** `deterministic`, `llm_review` or `user`.
- **Binding:** the Gate executes only signed decisions whose `request_hash` matches the request exactly.

**How signing works:** HMAC-SHA256 over canonical JSON (object keys sorted at every level). Signatures are tied to their purpose, so a signed plan can never be replayed as a signed decision or a signed prompt.

---

## 5. The Trust Factor system

### 5.1 Pipeline

```
fetch → render in headless browser (compute visibility)
      → strip hidden content (score 0, never delivered)
      → segment (site template → structural markup → heuristics)
      → classify region type → identify author
      → score → filter by plan.reads → label → deliver to A
```

An LLM never does the classification. It would have to read the content, which means it could be injected.

### 5.2 Region types and their maximum scores

| Region type | Max trust | Notes |
|---|---|---|
| `operator_legal` | 90 | Privacy policy, terms of service |
| `operator_content` / `operator_ui` | 85 | The site's own pages and interface |
| `product_listing` | 80 | Listings on the retailer's own site |
| `editorial` | 75 | Articles from the publisher's staff |
| `search_snippet` | 50 | Third-party text shown on a search page. **Inherits the result site's score**, capped at 50 |
| `ugc_post` | 40 | Posts, issues, video descriptions (UGC = user-generated content) |
| `ugc_review` | 30 | |
| `profile` | 30 | |
| `ugc_comment` | 30 | Unknown authors start at 15 |
| `ad` | 10 | |
| `embedded_third_party` | (own origin) | Iframes and embeds are scored as their own site |
| `user_content` | 90 | The user's own files and notes. Usually confidential |
| `message` | 60 | Email, chat, invites. Scored by sender (section 5.4) |
| `unclassified` | 10 | Unknown defaults to low |
| `hidden` | 0 | Stripped before delivery |

### 5.3 Scoring

```
trust(region) = clamp( min(ceiling(type), domain_score, author_score) − penalties, 0, 95 )
```

- **Domain score:** unknown sites start at 20, adjusted for domain age, popularity rank, verified ownership, category and incident history. Domains registered in the last 30 days are capped at 5. Customers can pin their own domains, but a customer's internal wiki is still user-generated content.
- **Author score** (the Counter-Strike part): account age, verification, karma or subscriber count, and report history. Each platform needs its own adapter. Anonymous authors score 15.
- **Penalties** (these can only lower the score):
  - text addressed to an AI or agent
  - imperative instructions phrased like tool calls
  - invisible Unicode (zero-width characters, the tag block)
  - visible text that doesn't match the accessibility text
  - very recent edits to normally stable pages
- **Web content is capped at 95.** Legitimate sites get compromised.

### 5.4 Sources other than the web

| Source | How it's scored |
|---|---|
| Email | Sender passes DMARC and is in contacts: 60. Passes DMARC but unknown: 25. Fails authentication: 5. Attachments score as the sender, capped. |
| Calendar invites | Scored by the organizer, the same way as an email sender |
| User's own files | Written by the user: 90. Shared by someone else: that author's score |
| Third-party APIs | Field by field, using the region mapping in the tool manifest |
| Shell or code output | Output from running untrusted code is scored as untrusted |
| Memory | Each item keeps its original label. Recalling it counts as a read at that trust level |

### 5.5 Three trust levels

| Level | How it's computed | What it controls |
|---|---|---|
| Region trust | Section 5.3 | The input to the other two |
| **Context trust** | The minimum region trust delivered to this A instance. It only goes down | The strictness band B applies |
| **Argument trust** | The trust of the source the Gate traced the value to. Values it can't trace count as 0 | Each individual decision |

Argument trust answers "where did this value come from?" Context trust answers "what could have influenced this choice?" You need both. Influence attacks produce values that trace to a trustworthy source even though the choice itself was manipulated.

### 5.6 Reading only what the plan needs

The Gate delivers only the region types listed in `plan.reads`. If the plan doesn't need comments, A never sees them. Most of the attack surface disappears this way, at no cost.

---

## 6. Lifecycle

### Phase 0: Ingress
The user sends a prompt. Ingress authenticates the user, separates instructions from pasted or attached data (the data gets its own label), signs the prompt, and sends it **separately** to A and to B. B checks the signature, so the prompt never reaches B by way of A.

### Phase 1: Planning (both sides still clean)
A and B both draft plans. Both contexts are clean, so they can exchange drafts freely. B merges the drafts into the Plan of Record and signs it. If the two drafts disagree materially, the prompt is ambiguous, and B asks the user now, before anything has been read. If the task is driven by its data ("do what this email says"), B marks the affected steps as needing user confirmation.

### Phase 2: Execution loop
```
A → request → Gate:
   1. validate schema, resolve refs, check budget
   2. trace argument sources, run DLP
   3. deterministic policy check  → allow | deny | gray | confirm
   4. gray → B's LLM reviews the metadata view → approve | deny | confirm
   5. confirm → Console shows the user the real values and where they came from
   6. execute through the Tool Proxy (credentials from the Vault)
   7. label results → filter → deliver to A → update context trust
   8. write everything to the ledger
```

### Phase 3: Output
The final answer to the user is also an output channel, so it gets checked:
- Links from low-trust regions are flagged.
- Remote images never load automatically.
- Claims drawn only from low-trust regions can optionally be marked.

### Recovery: kill, quarantine, restart

A denial shouldn't mean a failed task. When the Gate sees a **takeover signal**, the runtime kills that Worker
instance and starts a fresh one on the same signed plan, with the cause quarantined:

- **Takeover signals** (deterministic): a tool or step outside the plan; a destination that traces to untrusted content;
  a raw link or address typed into an egress content arg; an amendment asking for a new destination after a low-trust
  read; a watchdog trip. Ordinary mistakes (wrong type, missing arg) only get the usual coarse code back.
- **Quarantine the smallest cause.** Provenance names the source of the offending value (e.g. one `ugc_review` region
  on `domain#7` by an unknown author), so the Gate withholds exactly that region, by content hash, for the rest of the
  task, and the domain's score can only go down. When nothing traces (an off-plan tool, a stall), it withholds every
  low-trust region read since the last completed step.
- **The plan doesn't change.** It was made on a clean side, so it is reused as signed. The quarantine is a Gate-side,
  tighten-only filter bound to the new instance and written to the ledger (`recovered`, with the quarantine list).
- **Handoff:** completed steps carry over as typed refs with their labels (as for rotation below). Steps whose
  outputs touched the quarantined content run again through the filter.
- **Bounded:** at most two recoveries per task. Then the task pauses and the user is asked, which also caps what an
  attacker can spend by planting payloads everywhere.
- **The user is told:** the final report says what was withheld and why ("1 review was withheld: it contained
  instructions aimed at the agent").

### Rotating instances
Trust only goes down, so the way back to full trust is a **fresh instance of A**:
- Every new task starts a new A.
- Partway through a task, if the band falls to 0–19 and tier 2–3 steps remain, the Gate can start a fresh A.
- The handoff carries only plan progress, plus earlier results as typed references with their labels. Never A's raw context.
- Conversation history sits behind a recall tool and is not preloaded.

---

## 7. How the Supervisor decides

### 7.1 Stage 1: deterministic checks (every request)
1. **Plan:** right step, right tool, budget left, order allowed.
2. **Roles:** destination arguments trace to allowed sources with enough trust. Selectors are known references. Control arguments are in range.
3. **Confidentiality:** labels on content arguments are compatible with the destination.
4. **Band:** apply the rules for the current strictness band.

### 7.2 Strictness bands (set by context trust)

| Context trust | Tier 1 (egress) | Tier 2 (write) | Tier 3 (irreversible) |
|---|---|---|---|
| 80–100 | Code checks only | Code checks only | Code checks only |
| 50–79 | Code checks only | Code checks + LLM review | Code checks + LLM review |
| 20–49 | Domains in the plan: automatic. New domains: LLM review | LLM review | LLM review, plus user confirmation unless every destination argument has trust ≥ 90 |
| 0–19 | Destinations listed in the plan only | User confirmation | User confirmation |

### 7.3 Stage 2: LLM review (gray zone only)
- **Input:** the metadata view plus the signed prompt and the plan. Nothing else.
- **Question:** "Does this request serve the user's prompt, within the plan?"
- **Output:** constrained to `approve | deny | confirm_user`.
- It can't override a Stage 1 denial.

### 7.4 Denials and amendments
- **Denials** go back to A with only a rough reason code. A denial that is a takeover signal triggers recovery (section 6) instead. After three denials on the same step, the task pauses and the user is asked. This stops A from probing variations until one gets through.
- **Amendments** are typed requests, for example "add step: web.open with url from step2". New tier 0–1 steps are approved automatically. New tier 2–3 steps, or any new destination, need the user's confirmation.

---

## 8. Readers

Readers let the agent stay on autopilot while the risky reading happens somewhere else.

```json
{"reader":"extract","source":"ref:page12","regions":["ugc_review"],
 "schema":{"avg_rating":"float[0,5]/0.1","mentions_dead_pixels":"bool","best_listing":"ref"}}
```

- Every Reader is a fresh instance with no tools. Its context holds only the content, a fixed reader prompt and the output schema.
- **Allowed output types:** bool, enum (16 values or fewer), numbers with a range and precision, date, currency, `ref`, and short lists of these.
- **Strings are never returned.** URLs, email addresses and names come back as `ref`s. The Gate holds the real value, so attacker-written destinations never enter A's context.
- **Capacity budget:** 64 bits or less per call, worked out from the schema (bool = 1 bit, enum with n values = log₂ n bits, and so on). Anything over the budget is treated as free text and lowers A's context trust to the source's level.
- **Labels:** results keep their source label, so argument checks still apply. They don't lower A's context trust, because they can't carry instructions.
- **Residual risk:** a Reader can be manipulated into returning a *wrong* value. That's a data-integrity problem, and the label limits what it can trigger.

---

## 9. Integration (staying model-agnostic)

**Model adapters:** B and the Readers call models through one interface, `complete(messages, json_schema) → validated object`. Providers: Anthropic, OpenAI, Google, and open-weight models through OpenAI-compatible endpoints. If a provider lacks native structured output, the adapter validates and retries. Agent A is whatever the customer already runs.

**Ways to run Agent A:**
1. **Munix runtime (primary):** `munix run -- <agent command>`. Munix launches the agent in a sandbox (v1: a container
   with `--network none`; later OS sandboxes) and owns its stdio MCP channel and a local model gateway. The agent's code
   doesn't change; it is configured with Munix's MCP server and gateway URL and nothing else is reachable. If a hijacked
   agent stops listening to Munix it simply can't act. The runtime also gives recovery and the watchdog their power:
   only something above the agent can kill and restart it.
2. **MCP proxy (weaker, opt-in):** Munix as an MCP server the customer's existing agent connects to. Mediation then
   depends on the agent's other routes being closed by the deployment (an egress block, no shell), which Munix can't
   guarantee. Use it where the runtime can't wrap the agent; the sandbox makes a separate egress proxy unnecessary.
3. **SDK:** Python and TypeScript wrappers for LangGraph, the OpenAI Agents SDK and the Claude Agent SDK. Ship this later.

**Model gateway:** the agent's OpenAI- or Anthropic-compatible base URL points at the runtime, which forwards to the
provider and adds the key. Keys never enter the sandbox, and the watchdog counts calls and tokens here.

**Required: prompt ingress.** The customer's app sends user prompts through the Munix ingress API. Without it, B has no trustworthy prompt to plan from.

**Deployment:** self-hosted as a container or sidecar, because security buyers keep data in their own cloud. Everything is open source; threat-intelligence updates and region templates ship as versioned data in the repo.

**Isolation (prevents what the Integrity Seal detects):** run Munix as its own OS user (or container) and the Worker as another, with Munix's binaries, source, manifests, plans and config read-only to the Worker and Munix's process outside its reach. Then a hijacked agent with file or shell access can't edit Munix at all; the seal remains the tripwire for misconfigured deployments.

**Policy packs:** default tool manifests and policies for email, Slack, GitHub, the browser, the filesystem, shell and calendar.

---

## 10. Tech stack

| Area | Choice | Why |
|---|---|---|
| Gate core, policy engine, tracer, DLP | **Rust** | Memory safety and performance in one binary. You already use Rust for Remark |
| Policy language | Evaluate **Cedar** (AWS, written in Rust, open source) vs a small custom rule language | Deterministic, analyzable authorization. Labels become attributes on requests |
| Rendering and segmentation | Headless Chromium via CDP or Playwright, with declarative selector templates | Visibility has to be computed on the rendered page, not the raw HTML |
| Ledger | SQLite or Postgres plus a hash chain | Tamper-evident and easy to export |
| Signing | HMAC-SHA256 inside one deployment; Ed25519 across hosts | |
| SDKs and evaluation harness | Python and TypeScript | Where the agent frameworks are |

**Repository layout:**
```
munix/
  crates/        munix-core (M0, done) · munix-gate · munix-ledger (M1) · munix-supervisor ·
                 munix-adapters (M2) · munix-trust (M3) · munix-provenance (M4) · munix-readers (M5)
  xtask/         `cargo xtask schemas` regenerates /schemas from the Rust types
  schemas/       JSON Schemas for every wire type (generated; a test catches drift)
  manifests/     approved tool manifests and policy packs
  examples/      worked example: prompt, plan, request
  integrations/  runtime/ (munix run: sandbox, MCP channel, model gateway) · mcp-proxy/ (opt-in mode) · sdk-python/ sdk-ts/  (M6)
  templates/     site region templates (M3)
  eval/          AgentDojo harness, web benchmarks, adaptive red-team suite (M7)
  docs/
```

---

## 11. Evaluation

**Benchmarks:** AgentDojo, which reports usefulness and attack success side by side and has published CaMeL numbers to compare against. Plus web-agent injection benchmarks such as WASP, and Munix's own suite.

**Metrics:**

| Metric | v1 target |
|---|---|
| Attack success on tier 2–3 actions | ≤ 1% |
| Task success without attacks | within 5–7 points of an undefended agent (CaMeL: 77 vs 84) |
| Task success under attack | report it |
| **User confirmations per task** (the autopilot metric) | ≤ 1 per 10 tasks |
| Added latency per gated call | p50 ≤ 50 ms (code-only path); p50 ≤ 800 ms (LLM review path) |
| Token or cost overhead | report it |

**Baselines:**
- no defense
- CaMeL
- a detection classifier (such as Prompt Guard)
- a reviewer-only design (Task Shield style)

**Adaptive red-team suite** (written against Munix specifically, and kept running):
1. Planting payloads on high-trust regions and domains
2. Influence attacks: steering A to a wrong choice whose value traces to a trustworthy source
3. Tricking the agent into requesting plan amendments
4. Probing denials until something gets through
5. Manipulating Reader outputs
6. Covert channels: encoding data in the order or timing of calls
7. Getting attacker strings into the metadata view (fuzzing the redaction)
8. Evading DLP with base64, URL encoding, splitting across fields, homoglyphs
9. Abusing hidden text and Unicode
10. Swapping MCP tool descriptions after approval ("rug pull")
11. Tampering with Munix itself mid-task: editing a manifest, plan, config, source file, binary or launched tool, including edit-and-revert races (Integrity Seal)
12. Escaping the runtime: direct network calls, reading keys or `.env`, signalling or attaching to the Munix process, dropping the MCP channel
13. Disruption: payloads that make the agent wait, loop, re-read or burn tokens (watchdog, recovery and its cap)
14. Recovery abuse: planting payloads in many regions to force endless restarts, or to get legitimate content quarantined

---

## 12. Roadmap

Every milestone ends with exit criteria. The crates have clean ownership boundaries, so milestones can be built by parallel builder agents, each owning specific crates, plus a dedicated security-reviewer agent.

| # | Milestone | Exit criteria |
|---|---|---|
| **M0** ✅ | Freeze the spec: threat model, manifest, plan, request and decision schemas | Schemas published, with example manifests for 5 tools. **Done 2026-10-07:** `munix-core`, 10 schemas, 5 manifests, worked example, 32 tests |
| **M1** ✅ | Gate core: Tool Proxy, Vault placeholders, request validation, budgets, ledger, deterministic policy engine (plans written by hand) | A toy agent can act only through the Gate. Unsigned or altered requests are rejected. The ledger chain verifies. **Done 2026-10-08:** `munix-gate`, `munix-ledger`, toy agent, 205 tests |
| **M2** ✅ | Supervisor: planner, metadata view with redaction, two-stage approver, denials and amendments, two model adapters | A fuzz test shows no attacker string ever reaches B's model. `munix demo --attack` runs end to end with real models. **Done 2026-10-10:** `munix-supervisor`, `munix-adapters` (Anthropic, OpenAI-compatible/LM Studio, `agy` CLI, mock), `munix-cli`. The AgentDojo run moved to M7, since it needs the M6 integration to drive a real agent. Status and handoff: [STATUS.md](docs/STATUS.md) |
| **M3** | Trust Engine v1: render, strip hidden content, segment, classify, score; templates for the top 25 sites; domain scoring; filtering by plan; context trust and bands | Region classification ≥ 95% accurate on the template sites. Strictness bands enforced |
| **M4** | Provenance tracer and DLP: destination tracing, encoded variants, confidentiality labels | Destination tracing ≥ 99% on the test suite. Red-team items 7 and 8 pass |
| **M5** | Readers: typed schemas, capacity calculation, reference IDs for strings | Reader results never lower context trust. Requests over capacity are degraded to free text correctly |
| **M6** | Integration: Munix runtime (sandboxed launch, MCP channel, model gateway, watchdog, recovery), MCP proxy mode, Python SDK, Console reference UI | An existing MCP agent runs protected under `munix run` with no code changes and holds no keys |
| **M7** | Evaluation: AgentDojo, web benchmark, full red-team suite, published results | The section 11 targets are met or the gaps are documented. Results write-up published |
| **M8** | Design partners: policy packs, self-hosted packaging, hardening | 3–5 partners running real workflows |

---

## 13. How this differs from prior work

| | CaMeL / FIDES | Detection firewalls | Reviewer-only (Task Shield, AlignmentCheck) | **Munix** |
|---|---|---|---|---|
| Must you rewrite the agent? | Yes (custom interpreter) | No | No | **No** (run it under `munix run`) |
| Security from code, not models | Yes | No | No | **Yes** |
| Trust levels | Trusted or untrusted | Scores, which can be gamed | None | **Graded by region and author, and only goes down** |
| Protects the reviewer from injection | n/a (no reviewer) | n/a | No (it reads the untrusted content) | **Yes** (metadata view, attacker strings redacted) |
| Keeps the agent on autopilot | Strict policies cost task success | Yes, but bypassable | Yes, but bypassable | **Readers + bands + gray-zone review** |
| Tracks where arguments came from | Yes (exact) | No | No | **Yes** (references are exact; raw strings are traced) |

---

## 14. Known limitations

1. **Tasks driven by their data** ("do what the email says") can't safely run on autopilot. B detects these and requires confirmations up front.
2. **Rare sites:** long-tail sites default to low trust, which costs task success until templates or reputation data cover them.
3. **Free-text DLP:** paraphrased or heavily transformed secrets can slip past it. Destinations are robust; content is best-effort.
4. **Covert channels:** the order and timing of approved calls leak a little information. Accepted and documented.
5. **Influence attacks** are bounded, not prevented. Context trust and labels limit how far a manipulated choice can go.
6. **The plan caps usefulness:** a weak Supervisor model makes poor plans. The clean side needs a strong model.
7. **Integration is required:** without the ingress and complete mediation, the security claims don't hold. The runtime provides mediation by construction; the MCP-proxy mode depends on the deployment closing the agent's other routes.
8. **Templates need upkeep:** sites change their layout, so templates need monitoring and updates.
9. **Choosing among attacker-supplied links is a channel:** when the context holds private data, which of many attacker links the agent opens can encode bits. The policy sends low-trust step-derived egress to review whenever the context is private (`ConfidentialEgress`). The channel narrows, but doesn't close.
10. **Bare domains in text:** content args are scanned for URLs, emails and defanged forms, but not for scheme-less domains like `example.com` until the M4 tracer.

### Security review backlog

The M0 review (2026-10-07) found 0 critical, 4 high, 13 medium and 11 low issues.
- **Fixed in M1:** all 4 high and most mediums:
  - H2 header injection: `single_line` text and strict control-character rules;
  - H3 attachment content kept away from the Supervisor (`PromptView`, digest-only attachments);
  - H4 workspace files are `unclassified`;
  - H1 raw links in content denied;
  - context state can't be copied or reset;
  - over-budget typed values count as free text;
  - decisions bound to ticket and plan digest;
  - explicit DLP required;
  - trust floors for step-derived destinations;
  - strict ASCII machine values (no homoglyphs, userinfo or IP hosts);
  - printable-ASCII tool descriptions;
  - `Purpose::UserConfirmation`;
  - steering args constrained on every tier.

Deferred, with the milestone that owns each:

| Item | Milestone |
|---|---|
| Numeric ranges in manifests and value constraints (`equals`, `one_of`, `max`) in plans, for control args of tier-3 tools | M2 |
| Minimum trust floors by tier for step-derived steering args (validation accepts `min_trust: 0`, which is no floor) | M2 |
| Plans pin the manifest digests they were validated against; plan `version`/`parent` digest for amendments | M2 |
| `Verified<T>` wrapper so Gate APIs only accept verified plans and decisions; per-purpose keys (HKDF) and Ed25519 for the Ingress and Console signers | M2 |
| Metadata view prints only Gate-known ref ids and plan ids; `Finding.arg` and decision reasons become validated codes | M2 |
| Nonce freshness window and replay cache at Ingress | M2 |
| `Label` validating constructor (trust clamped to the region ceiling and `WEB_CAP`) | M3 |
| Content Filter strips bidi, tag and control characters from page text. Today the Gate rejects the whole output (`BadOutput`), which fails closed but costs usefulness | M3 |
| Raw-text tracing, bare-domain detection, DLP scanner (content confidentiality = max of context, scan and embedded facts) | M4 |
| Reader output validator: required fields, quantized numbers, real dates, a ref candidate cap; at least 1 bit charged per field; extra keys rejected on unit variants of internally tagged enums | M5 |
| Tool Proxy network hardening: WHATWG URL parsing, DNS pinning, redirect re-validation, private-address block, MIME header encoding | M6 |
| RFC 8785 canonical JSON and type-tagged digests, if non-Rust SDKs compute digests; rejecting duplicate map keys | M6 |
| Ledger: per-ledger id and timestamp in checkpoints, opening against the last checkpoint, off-host anchoring; `zeroize` for keys and credentials | M8 |

### Ledger file format

JSON Lines, exactly as `append` writes them; anything else fails `open`, which blocks duplicate-key and padding tricks. `serde_json`'s `float_roundtrip` is on workspace-wide, so logged floats reload bit for bit. There is one writer per file, enforced by an exclusive lock. On Windows that lock also blocks readers, so auditors use `entries()` or wait until the ledger is closed.

---

## 15. Open decisions

| Decision | Recommendation |
|---|---|
| Name | **Decided:** Munix Security |
| Language for the core | Rust |
| First integration | **Decided:** the Munix runtime (`munix run`): the agent runs sandboxed inside Munix. MCP proxy as an opt-in mode |
| Policy language | Prototype on Cedar first; build a custom one only if Cedar can't express labels cleanly |
| Default Supervisor model | A strong frontier model. Customers can override it |
| Licensing | **Decided:** fully open source under Apache-2.0. Gate, Supervisor, Trust Engine, templates, Console and integrations all ship in this repo |
| Who owns the confirmation UI | Munix provides an API plus a reference Console; customers can embed it |
| Number of site templates at launch | 25, chosen by traffic from design partners |
