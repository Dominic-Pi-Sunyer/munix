"""A stand-in for `munix bridge` that speaks the JSON-lines protocol in BRIDGE.md, for offline tests.

    python fake_bridge.py bridge --manifests <dir> --ledger <file>

It allows every call except those named in MUNIX_FAKE_DENY (comma-separated AgentDojo names), which get a denial
(`is_error` true) without ever asking Python to run the tool. An allowed call issues one `run_tool` with the
arguments unchanged and returns the `tool_result` output as JSON text. MUNIX_FAKE_MODE=die exits after `start`;
MUNIX_FAKE_MODE=hang never answers `start`.
"""

import json
import os
import sys
import time


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main() -> int:
    argv = sys.argv[1:]
    ledger = argv[argv.index("--ledger") + 1]
    deny = {n for n in os.environ.get("MUNIX_FAKE_DENY", "").split(",") if n}
    mode = os.environ.get("MUNIX_FAKE_MODE", "")
    entries = 0
    denied = 0

    def log(entry: dict) -> None:
        nonlocal entries
        entries += 1
        with open(ledger, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    for line in sys.stdin:
        msg = json.loads(line)
        op = msg["op"]
        if op == "start":
            if mode == "die":
                return 3
            if mode == "hang":
                time.sleep(60)
            log({"start": msg["prompt"]})
            send({"op": "started", "task": f"T-{os.getpid()}", "plan_steps": 1})
        elif op == "call":
            name, arguments = msg["name"], msg["arguments"]
            log({"call": name})
            if name in deny:
                denied += 1
                send({"op": "result", "text": "denied: policy", "is_error": True})
                continue
            send({"op": "run_tool", "name": name, "arguments": arguments})
            reply = json.loads(sys.stdin.readline())
            assert reply["op"] == "tool_result", reply
            if reply["ok"]:
                send({"op": "result", "text": json.dumps(reply["output"]), "is_error": False})
            else:
                send({"op": "result", "text": reply["error"], "is_error": True})
        elif op == "end":
            send(
                {
                    "op": "ended",
                    "context_trust": 100 - 10 * denied,
                    "ledger_entries": entries,
                    "ledger_verified": True,
                    "takeover": None,
                    "supervisor_usage": {"calls": 1, "prompt_tokens": 1000, "completion_tokens": 100},
                    "plan": "memory:exact" if "--plan-memory" in sys.argv else "planner",
                }
            )
            return 0
        else:
            send({"op": "error", "message": f"unknown op {op}"})
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
