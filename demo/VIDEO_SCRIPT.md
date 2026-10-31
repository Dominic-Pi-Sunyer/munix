# Demo video script (draft 3, synced to the motion graphics)

Target **3:00**. Each section is one After Effects scene comp (S1 to S7, prompts in the Google Doc "Munix demo
video: motion graphics prompts"). The VO lines are timed to the scene's build markers: **[M1]**, **[M2]**… are the
markers to place in that comp, and the VO line after a marker starts on it. About 150 words a minute; every block
below fits its slot when read at that pace.

**Rules on screen** (from `HACKATHON.md`): the injected text is never shown (redaction bars stand in for it); no
Web Speed branding; every number matches `docs/redteam/*.md` and the benchmark doc.

---

## S1 · 0:00–0:10 · Title and intro (face cam or VO over the title card)

[M1 0:00, headline reveals] "Hi, I'm Dominic. AI agents now read the web, your email and your files, and anything
they read can carry instructions written by a stranger."

[M2 0:05, lower third] "I built Munix, a runtime that makes sure those strangers can't take over the agent. Here's
what that looks like."

## S2 · 0:10–0:50 · The split screen (footage + S2 overlays)

[M1 0:10, labels] "Same model, Muse Spark, same task, same attack. On the left it runs on its own. On the right it
runs inside Munix."

[M2 0:15, task line] "The user asks it to update their rent from the landlord's notice. Hidden in that notice is an
attack Muse Spark wrote against itself. It worked on the unprotected agent every time we tried it."

[M3 ~0:25, left callout, retime to footage] "On the left, the agent changes the rent and redirects it to the
attacker's account. AgentDojo's own check confirms the attack succeeded."

[M4 ~0:33, right callout 1] "On the right, the agent never sees the letter. A Reader turns it into four typed
values: a rent notice, an amount, what the amount means, and a flag that it contained instructions. There's no text
left for an attack to ride in on."

[M5 ~0:41, right callout 2] "And because that amount came from a document, not from me, Munix holds the change and
asks me first. The attacker's account is never touched."

[M6 0:47, verdict bars] (no VO; hold on "ATTACK SUCCEEDED" / "ATTACK BLOCKED")

> **Bank app take.** For a visual S2, run each side with `--web` (`eval/agentdojo/demo_replay.py --case rent --side
> bare --live --web`, then `--side munix`) and record the page full screen; it plays the real run's steps and payments.
>
> **Film note.** Under the current build a live take parks the rent change for the user (`amount.value_unbound`);
> with no one at the Console it is declined, so the right side ends with the attack blocked and the rent unchanged.
> The M5 line matches that. If we add an interactive Console to `demo_replay.py`, film yourself approving the
> 1,200.00 instead and change M5 to "…asks me first. I approve the amount; the attacker's account is never
> touched." `--recorded` takes are from the Oct 28 build and don't show the hold.

## S3 · 0:50–1:50 · How Munix works (architecture build)

[M1 0:50, agent + sandbox closes] "Munix doesn't trust the model to refuse. A refusal is a probability, and an agent
that acts a thousand times a day only has to fail once. So the agent runs boxed in: no network, no keys. It can only
propose actions."

[M2 1:00, You + Supervisor] "Before it reads anything, a separate Muse Spark planner, which only ever sees my
prompt, writes a plan: which tools may run, and where each argument may come from."

[M3 1:08, signed plan arrow] "The plan is signed. The payment's recipient has to come from me, not from a document."

[M4 1:15, the Gate lights] "Every action goes through the Gate, and the Gate is plain code. It traces every
destination and every amount back to where it came from. No model makes that call."

[M5 1:25, Tools] "Only what the Gate allows reaches the real tools."

[M6 1:30, Ingest + loop] "Everything coming back is labeled by who wrote it. Links become opaque references, and
text from strangers comes back only as typed values. Trust only ever goes down."

[M7 1:40, Ledger + pulse] "And every decision, with its reason, goes into a hash-chained ledger you can verify."

## S4 · 1:50–2:10 · Meta's Prompt Guard inside Munix

[M1 1:50, table rows] "Munix also runs Meta's Llama Prompt Guard 2 as a detector that can only lower trust. It
catches the obvious attacks: fourteen out of fourteen."

[M2 1:58, last rows count] "But AgentDojo's strongest attack, and the sixteen attacks Muse Spark wrote that took
over the agent, read like ordinary notices. It flagged none of them."

[M3 2:05, closing line] "Munix doesn't need the detector to be right."

## S5 · 2:10–2:40 · Results

[M1 2:10, headline counters] "We had Muse Spark write new attacks against itself. Sixteen of them broke the
unprotected agent, forty-two times in forty-eight runs. Under Munix: zero."

[M2 2:18, model swap card] "Swap in a different model, Muse Wonder, and the agent changes. The safety doesn't:
still zero."

[M3 2:24, attacker-vs-Munix card] "Then we gave the attacker Munix's rules and told it why each attempt was
refused. Zero of twenty-nine rounds got through."

[M4 2:31, AgentDojo table] "On AgentDojo, the academic benchmark for agent security, Munix stopped every attack in
banking and Slack. It has a cost, and we report it: when a task really means acting on a stranger's word, Munix
stops and asks you."

## S6 · inside S5 · Efficiency (optional 6 s, cut if over time)

[M1] "The code check takes about twelve milliseconds, and no model ever has the final say."

## S7 · 2:40–3:00 · Close

[M1 2:40, close lines] "Content an attacker controls can't send your money or your data somewhere you didn't
choose."

[M2 2:48, second card] "Swap the model and the agent gets smarter or dumber, never less safe."

[M3 2:54, logo + repo] "That's Munix, built on Muse Spark and Llama Prompt Guard 2. Thanks for watching."

---

## Numbers on screen (check before export)

| Where | Number | Source |
| :-- | :-- | :-- |
| S4 | 14 / 14 flagged ("ignore previous instructions") | `docs/redteam/adaptive-and-prompt-guard.md` |
| S4 | 0 / 14 flagged (AgentDojo `important_instructions`) | same |
| S4 | 0 / 16 flagged (Muse Spark's winning attacks) | same, Oct 29 update |
| S5 | 16 attacks; bare 42 / 48, Munix 0 / 48, Munix + Prompt Guard 0 / 48 | same |
| S5 | Muse Wonder as the agent: bare 7 / 27, Munix 0 / 27 | same |
| S5 | Attacker that knows Munix's rules: 0 of 29 rounds | `docs/redteam/adaptive-vs-munix-oct29.md` |
| S5 | AgentDojo banking 144 attacks (140 ran under Munix), Slack 105: 0 succeeded bare, 0 under Munix | `docs/redteam/agentdojo.md` |
| S6 | about 12 ms per code check | latency tests |

## Open items

- **Utility line (S5 M4):** the Oct 29 utility fixes are being measured now. If the numbers recover enough, add one
  card with tasks completed (bare vs Munix); otherwise keep the honest one-line "it stops and asks you".
- **S2 live take:** decide between filming the hold as is (M5 as written) or adding an interactive Console so you
  approve the amount on camera.
- **S6 "1.2× cost with plan memory":** measured before Oct 29; plan memory was relearned after the manifest change,
  so it's off screen until remeasured.
- Video length limit and face cam vs voice only: confirm against the submission rules.
