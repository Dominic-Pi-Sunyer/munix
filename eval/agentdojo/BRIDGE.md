# The Munix bridge protocol (contract)

`munix bridge` is the process that holds a real Munix Gate for one AgentDojo task. The Python side
(`munix_executor.py`) starts one per task, sends it every tool call the model makes, and runs the tool on
AgentDojo's environment whenever the Gate allows it. All security decisions stay in Rust, made by the same
`GateFront` that `munix run` uses. Python never decides anything; it only carries calls and results.

## Process

```
munix bridge --manifests <dir> --ledger <file> [--plan <plan.yaml> [--no-reviewer]] [--simulated-user]
```

- **stdin and stdout:** JSON lines, one object per line, UTF-8. Diagnostics go to stderr.
- **Configuration:** `.env` and the environment, as in `munix run`. That's `MODEL_API_KEY`, `MUNIX_SUPERVISOR_MODEL`
  and the per-role efforts; the reviewer and planner are Muse Spark.
- **`--manifests`:** the catalog, `*.yaml` in the directory, such as `eval/agentdojo/manifests/banking`.
- **`--plan`:** a hand-written plan, rewritten with the new ids as `munix run` does. Without it, the Muse Spark
  planner writes the plan from the prompt and the catalog.
- **No sandbox, model gateway, watchdog, recovery or Integrity Seal.** The agent runs in AgentDojo's process (see
  `DESIGN.md`, "Invariant note").

## Messages, in order

1. **Python → bridge**, once: `{"op":"start","prompt":"<the user task's prompt>"}`.
2. **Bridge → Python:** `{"op":"started","task":"T-…","plan_steps":N}`, or `{"op":"error","message":"…"}` followed
   by exit code 2.
3. **Then, any number of times:**
   - Python sends `{"op":"call","name":"<agentdojo tool name, e.g. send_money>","arguments":{…}}`.
   - The bridge passes the call to `GateFront`'s MCP `call_tool`, with the tool's MCP name
     `<suite>_<agentdojo name>`, e.g. `banking_send_money`.
   - **If the Gate executes the tool,** the bridge first sends `{"op":"run_tool","name":"send_money",
     "arguments":{…resolved…}}`. The arguments have every ref replaced by its real value. Python runs the function
     on the environment and answers:
     - `{"op":"tool_result","ok":true,"output":{<manifest field>: value, …}}`, or
     - `{"op":"tool_result","ok":false,"error":"<short text>"}`.
   - The bridge then sends the call's outcome: `{"op":"result","text":"<what the model sees>","is_error":bool}`.
     `text` is exactly what `call_tool` returns: delivered fields as JSON, or a coarse denial.
4. **Python → bridge:** `{"op":"end"}`. The bridge answers
   `{"op":"ended","context_trust":N,"ledger_entries":N,"ledger_verified":bool,"takeover":"<code>"|null}` and exits
   with code 0.

If stdin closes early, the bridge writes nothing more and exits 0. A malformed line gets `{"op":"error",…}` and
exit code 2.

## Rules

- **Remote tools:** each manifest's tool is registered as a remote `Tool`. Its `call` sends `run_tool` and blocks
  for the matching `tool_result`. `ok:false` becomes `ToolFailure::Upstream`.
- **No human:** the Console is a confirmer that always answers no. Nothing is ever approved for the user.
- **`--simulated-user`:** replaces that flat no with a deterministic, clearly labeled stand-in for a careful user
  (evaluation only; `munix run` never uses it). It approves a Console request only when every destination and
  selector argument traces to the prompt, the user's data or a store, or to a record of trust 80 or more, and denies
  everything else, including any untraced value. Its decisions carry the ledger reason `console.simulated_user`
  instead of `console.user`.
- **Gray zone:** gray-zone calls go to the Muse Spark reviewer. Anything it would hand to the user is therefore
  denied.
- **Takeovers:** after a takeover the Gate halts the task, and every later `call` gets `Halted` as its result. The
  bridge keeps serving until `end`.
- **Tool names:** `<suite>.<agentdojo name>`, e.g. `banking.send_money`, a valid `ToolName`.
- **Outputs:** the Python converter turns a function's return value into the manifest's output fields, all of them
  flat. Lists of records become parallel arrays, so `recipients[i]`, `amounts[i]` and so on describe record `i`.
