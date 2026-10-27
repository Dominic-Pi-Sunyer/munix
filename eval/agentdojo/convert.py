"""Turn AgentDojo banking tool results into the flat output fields of the Munix manifests.

The manifests in `manifests/banking/` are the source of truth for the field names. `to_fields` returns exactly
those fields for a tool, nothing more and nothing less. Lists of transactions become parallel arrays: element i of
every array describes transaction i.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
MANIFEST_DIR = HERE / "manifests" / "banking"
PREFIX = "banking."
BENCHMARK_VERSION = "v1.2.2"


def load_manifests(directory: Path = MANIFEST_DIR) -> dict[str, dict]:
    """Manifests by AgentDojo tool name (`send_money`), without the `banking.` prefix."""
    out = {}
    for path in sorted(directory.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        tool = doc["tool"]
        if not tool.startswith(PREFIX):
            raise ValueError(f"{path.name}: tool name must start with {PREFIX!r}")
        out[tool.removeprefix(PREFIX)] = doc
    return out


def banking_tool_names() -> list[str]:
    from agentdojo.task_suite.load_suites import get_suite

    return sorted(t.name for t in get_suite(BENCHMARK_VERSION, "banking").tools)


MANIFESTS = load_manifests()
_missing = sorted(set(banking_tool_names()) - set(MANIFESTS))
assert not _missing, f"banking tools without a manifest: {_missing}"

def _user_iban(env) -> str:
    """The user's own IBAN, from the environment. AgentDojo writes the user as "me" in transaction records; the
    labels need the real account, so a missing environment is an error rather than a guessed value."""
    iban = getattr(getattr(env, "bank_account", None), "iban", None)
    if not isinstance(iban, str) or not iban:
        raise ValueError("get_most_recent_transactions needs the environment (env.bank_account.iban) to name the user")
    return iban


def _recent_transactions(items, env) -> dict:
    """Per-row parallel arrays, labeled by who wrote each value. A payment the user sent: the user chose the
    recipient and wrote the subject. An incoming payment: the sender and the subject are the sender's, so they are
    attacker-choosable, while the user's own IBAN is the recipient."""
    me = _user_iban(env)
    ids, sent_by_me, amounts, dates, recurring = ([] for _ in range(5))
    paid_to, paid_by, my_subjects, their_subjects = ([] for _ in range(4))
    for t in items:
        mine = t.recipient != "me"  # AgentDojo's incoming payments name the user "me" as the recipient
        ids.append(t.id)
        sent_by_me.append(mine)
        paid_to.append(t.recipient if mine else me)
        paid_by.append(me if mine else t.sender)
        my_subjects.append(t.subject if mine else "")
        their_subjects.append("" if mine else t.subject)
        amounts.append(float(t.amount))
        dates.append(t.date)
        recurring.append(bool(t.recurring))
    return {
        "ids": ids,
        "paid_to": paid_to,
        "paid_by": paid_by,
        "sent_by_me": sent_by_me,
        "amounts": amounts,
        "my_subjects": my_subjects,
        "their_subjects": their_subjects,
        "dates": dates,
        "recurring": recurring,
    }


def _scheduled_transactions(items) -> dict:
    """Scheduled payments are all the user's own: the user created them, so every field is the user's data."""
    ids, counterparties, sent_by_me, amounts, subjects, dates, recurring = ([] for _ in range(7))
    for t in items:
        mine = t.recipient != "me"
        ids.append(t.id)
        counterparties.append(t.recipient if mine else t.sender)
        sent_by_me.append(mine)
        amounts.append(float(t.amount))
        subjects.append(t.subject)
        dates.append(t.date)
        recurring.append(bool(t.recurring))
    return {
        "ids": ids,
        "counterparties": counterparties,
        "sent_by_me": sent_by_me,
        "amounts": amounts,
        "subjects": subjects,
        "dates": dates,
        "recurring": recurring,
    }


def to_fields(tool_name: str, result, env=None) -> dict:
    """Convert the return value of banking function `tool_name` into its manifest's output fields.

    `tool_name` is the AgentDojo name (`send_money`); a `banking.` prefix is accepted too. `env` is the
    environment the function ran on; `get_most_recent_transactions` needs it for the user's own IBAN (ValueError
    without it).
    """
    name = tool_name.removeprefix(PREFIX)
    if name not in MANIFESTS:
        raise KeyError(f"no banking manifest for tool {tool_name!r}")
    if name == "get_most_recent_transactions":
        fields = _recent_transactions(result, env)
    elif name == "get_scheduled_transactions":
        fields = _scheduled_transactions(result)
    elif name == "get_iban":
        fields = {"iban": str(result)}
    elif name == "get_balance":
        fields = {"balance": float(result)}
    elif name == "read_file":
        fields = {"content": str(result)}
    elif name in ("get_user_info", "update_user_info"):
        fields = {k: str(result[k]) for k in ("first_name", "last_name", "street", "city")}
    else:
        # send_money, schedule_transaction, update_scheduled_transaction, update_password: {"message": "..."}
        if isinstance(result, BaseModel):
            result = result.model_dump()
        fields = {"message": str(result["message"])}
    expected = set(MANIFESTS[name]["output"])
    if set(fields) != expected:
        raise ValueError(f"{name}: converted fields {sorted(fields)} differ from the manifest's {sorted(expected)}")
    return fields
