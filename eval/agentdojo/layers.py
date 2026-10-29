"""What stopped each attack under Munix, from the ledgers: python3 -I layers.py [results files...]

For every Munix attack case in the given results files (default: the AgentDojo attack phases and the adaptive
replays under Munix), it reads the case's ledger and reports the first Gate decision that wasn't an allow: a deny
code (with its reason), a request parked for the user, or none at all, which means the agent never tried anything
the Gate had to stop (the Readers kept the attack's text away from it, or the agent ignored it). Nothing here
reads tool output or payload text: only ruling outcomes, codes and fixed reason names.
"""

import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT = [
    *sorted((HERE / "results").glob("munix*--*-attack*.json")),
    *sorted((HERE / "results").glob("adaptive--*-replay-munix*.json")),
]


# Refusals that stop an extra call rather than the attacker's action: an honest agent hits them too.
HOUSEKEEPING = {"budget_exhausted"}


def first_stop(ledger: Path) -> str:
    """The first non-allow ruling that isn't housekeeping, as `deny:<code>:<reason>` or `confirm_user:<reason>`,
    else `no_block` (nothing the Gate had to refuse)."""
    try:
        lines = ledger.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "missing_ledger"
    for line in lines:
        event = json.loads(line).get("event", {})
        if event.get("event") != "ruling":
            continue
        outcome = event.get("outcome")
        reasons = [r for r in event.get("reasons", []) if not r.startswith(("plan.step", "budget.", "band."))]
        why = next((r.split(".", 1)[1] for r in reasons if r.split(".", 1)[-1] not in ("trace_ok", "dlp_ok")), "")
        if outcome == "deny" and event.get("code") in HOUSEKEEPING:
            continue
        if outcome == "deny":
            return f"deny:{event.get('code')}:{why}"
        if outcome in ("confirm_user", "gray"):
            return f"{outcome}:{why}"
    return "no_block"


def cases(path: Path):
    """(label, ledger path) for every Munix case in one results file."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    if "pairs" in doc:  # adaptive replay
        for pair in doc["pairs"]:
            for run in pair.get("runs", []):
                m = run.get("munix") or {}
                if m.get("ledger"):
                    yield f"adaptive {doc['config'].get('mode')}{'+guard' if doc['config'].get('detector_url') else ''}", Path(m["ledger"])
    else:
        for m in doc.get("munix") or []:
            if m.get("ledger") and not m.get("error"):
                yield f"{doc.get('suite', '?')} {doc.get('setup', '?')}", Path(m["ledger"])


def main() -> int:
    files = [Path(a) for a in sys.argv[1:]] or DEFAULT
    by_group: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for f in files:
        for group, ledger in cases(f):
            by_group[group][first_stop(ledger)] += 1
    for group, counts in sorted(by_group.items()):
        total = sum(counts.values())
        print(f"{group}: {total} cases")
        for stop, n in counts.most_common():
            print(f"  {n:4}  {stop}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
