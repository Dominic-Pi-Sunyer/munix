"""The Meta API credit floor: a hard stop shared by every paid evaluation run, so the demo always has credit left.

    python3 scripts/credit.py set 41.20            # the balance the Meta dashboard shows now (floor stays $25)
    python3 scripts/credit.py set 41.20 --floor 30
    python3 scripts/credit.py show

State lives in `.credit.json` at the repo root (gitignored): the balance as last read from the dashboard, the floor,
and the estimated spend charged since. Paid runners (`eval/agentdojo/run.py`, `adaptive.py`, `smoke.py`,
`scripts/redteam_bare.py`) check it before every case and charge their spend as they go. They refuse to start
without the file, and they stop once the estimated balance is at or below the floor. A run can go below the floor by
at most the one case in flight. Parallel runs share the file under a lock, so their spend adds up.

`munix run` (the demo) is not stopped by the floor, which is what the floor is for. Demo runs and anything else
spent outside these runners are not charged here, so re-run `set` from the dashboard now and then.
"""

import argparse
import fcntl
import json
import os
import sys
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# MUNIX_CREDIT_FILE points tests at a scratch file.
FILE = Path(os.environ.get("MUNIX_CREDIT_FILE") or ROOT / ".credit.json")
DEFAULT_FLOOR = 25.0


class CreditError(Exception):
    """No usable credit state, or the balance is at the floor: a paid run must not start or go on."""


@contextmanager
def _locked(path: Path):
    lock = path.with_name(path.name + ".lock")
    with open(lock, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _read(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        balance, floor, spent = float(state["balance_usd"]), float(state["floor_usd"]), float(state["spent_since_usd"])
    except FileNotFoundError:
        raise CreditError(
            f"no credit state at {path.name}: run `python3 scripts/credit.py set <balance from the Meta dashboard>`"
        ) from None
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise CreditError(f"{path.name} is unreadable ({type(e).__name__}); run `credit.py set` again") from None
    return {**state, "balance_usd": balance, "floor_usd": floor, "spent_since_usd": spent}


def _write(path: Path, state: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def remaining(state: dict) -> float:
    return state["balance_usd"] - state["spent_since_usd"]


def check(path: Path | None = None) -> float:
    """The estimated balance now. Raises CreditError when there is no state or the balance is at the floor."""
    path = path or FILE
    state = _read(path)
    left = remaining(state)
    if left <= state["floor_usd"]:
        raise CreditError(f"estimated balance ${left:.2f} is at the ${state['floor_usd']:.2f} floor kept for the demo")
    return left


def charge(usd: float, path: Path | None = None) -> float:
    """Adds `usd` of estimated spend and returns the estimated balance. Never raises for being under the floor."""
    path = path or FILE
    if usd <= 0:
        return remaining(_read(path))
    with _locked(path):
        state = _read(path)
        state["spent_since_usd"] = round(state["spent_since_usd"] + usd, 6)
        _write(path, state)
    return remaining(state)


def set_balance(balance: float, floor: float = DEFAULT_FLOOR, path: Path | None = None) -> dict:
    path = path or FILE
    state = {
        "balance_usd": round(balance, 4),
        "floor_usd": floor,
        "spent_since_usd": 0.0,
        "as_of": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with _locked(path):
        _write(path, state)
    return state


class Meter:
    """Charges one run's spend to the shared state. `spent` returns the run's total estimated spend so far."""

    def __init__(self, spent: Callable[[], float], path: Path | None = None) -> None:
        self.spent = spent
        self.path = path or FILE
        self.charged = 0.0

    def settle(self) -> float:
        """Charges what was spent since the last settle; returns the estimated balance."""
        total = self.spent()
        delta = total - self.charged
        self.charged = total
        return charge(delta, self.path)

    def stop_reason(self) -> str | None:
        """Settles, then "credit_floor" if the balance is at the floor (or the state is gone), else None."""
        try:
            self.settle()
            check(self.path)
        except CreditError as e:
            print(f"credit: {e}", file=sys.stderr)
            return "credit_floor"
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set", help="record the balance the Meta dashboard shows now")
    s.add_argument("balance", type=float)
    s.add_argument("--floor", type=float, default=DEFAULT_FLOOR)
    sub.add_parser("show")
    args = ap.parse_args()
    if args.cmd == "set":
        if args.balance < 0 or args.floor < 0:
            ap.error("balance and floor must be 0 or more")
        state = set_balance(args.balance, args.floor)
        print(f"balance ${state['balance_usd']:.2f}, floor ${state['floor_usd']:.2f}: paid runs may spend about "
              f"${max(0.0, state['balance_usd'] - state['floor_usd']):.2f}")
        return 0
    try:
        state = _read(FILE)
    except CreditError as e:
        print(e, file=sys.stderr)
        return 1
    left = remaining(state)
    print(f"balance ${state['balance_usd']:.2f} as of {state.get('as_of', '?')}, spent since ${state['spent_since_usd']:.2f}, "
          f"estimated now ${left:.2f}, floor ${state['floor_usd']:.2f}, room ${max(0.0, left - state['floor_usd']):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
