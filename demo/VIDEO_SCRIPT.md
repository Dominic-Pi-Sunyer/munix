# Demo video script (draft 5, synced to the motion graphics, with face cam)

Target **3:00**. Each section is one After Effects scene comp (S1 to S7, prompts in the Google Doc "Munix demo
video: motion graphics prompts"). The VO lines are timed to the scene's build markers: **[M1]**, **[M2]**… are the
markers to place in that comp, and the VO line after a marker starts on it. About 150 words a minute.

**Rules on screen** (from `HACKATHON.md`): the injected text is never shown (redaction bars stand in for it); no
Web Speed branding; every number matches `docs/redteam/*.md` and the benchmark doc.

---

## S1 · 0:00–0:10 · Title and intro (face cam)

[M1 0:00, face cam, headline reveals over the shot] "Hi, I'm Dominic. AI agents now read the web, your email and
your files, and anything they read can carry instructions written by a stranger."

[M2 0:05, face cam, name lower third] "I built Munix, a runtime that makes sure those strangers can't turn the
agent's tools against you. Here's what that looks like."

> **Face cam note.** Three pieces are on camera, about 35 s of the 3:00: S1 (0:00–0:10), the opening of S3 M1
> (0:50–1:01) and S7 M1–M2 (2:40–2:54). Everything else is screen footage or motion graphics with VO. Record them
> last, after the demo is cut, so each line fits its slot. Frame at eye level with a window in front of you and a
> plain background, and keep the same framing and shirt for all three so they cut together. Use the same mic as the
> VO, so the voice doesn't change between camera and screen. Do three takes of each line and pick in the edit.

## S2 · 0:10–0:50 · The split screen (bank app footage + S2 overlays)

[M1 0:10, labels] "Same model, Muse Spark, same task, same attack. On the left it runs on its own. On the right it
runs inside Munix."

[M2 0:15, task line] "The user asks it to update their rent from the landlord's notice. Hidden in that notice is an
attack Muse Spark wrote against itself. It takes over the unprotected agent in most runs."

[M3 ~0:25, left callout, retime to footage] "On the left, the agent changes the rent and redirects it to the
attacker's account. AgentDojo's own check confirms the attack succeeded."

[M4 ~0:33, right callout 1] "On the right, the agent never sees the letter. A Reader turns it into four typed
values: a rent notice, an amount, what the amount means, and a flag that it contained instructions. There's no text
left for an attack to ride in on."

[M5 ~0:41, right callout 2] "And because that new amount came from a letter, not from me, the Gate refuses the
change and stops the agent. The attacker gets nothing."

[M6 0:47, verdict bars] (no VO; hold on "ATTACK SUCCEEDED" / "ATTACK BLOCKED")

> **Film note.** Film each side as the bank app page and record it full screen:
> `eval/agentdojo/demo_replay.py --case rent --side bare --live --web`, then the same with `--side munix`. The page
> plays the real run: the agent's steps, the scheduled payments before and after, and on the right the Gate's
> rulings. The bare agent sometimes ignores the attack, so retake until it lands. Each live take costs a few cents.

## S3 · 0:50–1:50 · How Munix works (face cam, then architecture build)

[M1 0:50, face cam for the first two sentences; cut to the build on "So the agent runs boxed in" as the sandbox
closes] "Munix doesn't trust the model to refuse. A refusal is a probability, and an agent that acts a thousand times
a day only has to fail once. So the agent runs boxed in: no network, no keys. It can only propose actions."

[M2 1:00, You + Supervisor] "Before it reads anything, a separate Muse Spark planner, which only ever sees my
prompt, writes a plan: which tools may run, and where each argument may come from."

[M3 1:08, signed plan arrow] "The plan is signed. The payment's recipient has to come from me, not from a document."

[M4 1:15, the Gate lights] "Every action goes through the Gate, and the Gate is plain code. It traces every
destination and every amount back to where it came from. No model makes that call."

[M5 1:25, Tools] "Only what the Gate allows reaches the real tools."

[M6 1:30, Ingest + loop] "Everything coming back is labeled by who wrote it. Links become opaque references, and text
from strangers comes back only as typed values. Trust only ever goes down."

[M7 1:40, Ledger + pulse] "And every decision, with its reason, goes into a hash-chained ledger you can verify."

## S4 · 1:50–2:10 · Meta's Prompt Guard inside Munix

[M1 1:50, table rows] "Munix also runs Meta's Llama Prompt Guard 2 as a detector that can only lower trust. It
catches the obvious attacks: fourteen out of fourteen."

[M2 1:58, last rows count] "But AgentDojo's strongest attack, and the sixteen attacks Muse Spark wrote that took over
the agent, read like ordinary notices. It flagged none of them."

[M3 2:05, closing line] "Munix doesn't need the detector to be right."

## S5 · 2:10–2:40 · Results

[M1 2:10, headline counters] "We had Muse Spark write new attacks against itself. Sixteen of them broke the
unprotected agent, forty-two times in forty-eight runs. Under Munix: zero."

[M2 2:18, model swap card] "Swap in a different model, Muse Wonder, and the agent changes. The safety doesn't: still
zero."

[M3 2:24, attacker-vs-Munix card] "Then we gave the attacker Munix's rules and told it why each attempt was refused.
Zero of twenty-nine rounds got through."

[M4 2:31, AgentDojo table] "On AgentDojo, the academic benchmark for agent security, Munix stopped every attack in
banking, Slack and travel. It has a cost: when a task means relying on a stranger's word, it stops and asks you."

## S6 · inside S5 · Efficiency (optional 6 s, cut if over time)

[M1] "The code check takes about twelve milliseconds, and no model ever has the final say."

## S7 · 2:40–3:00 · Close (face cam, then logo card)

[M1 2:40, face cam, line as a lower third] "Content an attacker controls can't send your money or your data
somewhere you didn't choose."

[M2 2:48, face cam, line as a lower third] "Swap the model and the agent gets smarter or dumber, never less safe."

[M3 2:54, cut to logo + repo, VO] "That's Munix, built on Muse Spark and Llama Prompt Guard 2. Thanks for watching."

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
| S5 | AgentDojo, attacks that succeeded, bare / Munix: banking 0 / 0 (144 cases, default and `tool_knowledge` attacks), Slack 0 / 0 (105), travel 0 / 0 (140; AgentDojo's string check counts 1 and 2, all refusals that named the hotel) | `docs/redteam/agentdojo.md` |
| S6 | about 12 ms per code check | latency tests |
