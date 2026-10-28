"""Turn AgentDojo tool results (banking and Slack) into the flat output fields of the Munix manifests.

The manifests in `manifests/<suite>/` are the source of truth for the field names. `to_fields` returns exactly
those fields for a tool, nothing more and nothing less, except where a Reader sits in between (`READER_FIELDS`).
Lists of transactions become parallel arrays: element i of every array describes transaction i.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
SUITES = ("banking", "slack")
MANIFEST_DIR = HERE / "manifests" / "banking"  # the banking directory, kept under its old name
PREFIX = "banking."
BENCHMARK_VERSION = "v1.2.2"


def manifest_dir(suite: str) -> Path:
    return HERE / "manifests" / suite


# Third-party text the bridge's Readers (munix-readers::banking) take out of a tool's output before the Gate sees it:
# tool -> (the raw field `to_fields` returns, its region, the typed fields the Reader puts in its place).
SUITE_READER_FIELDS = {
    "banking": {
        "get_most_recent_transactions": ("their_subjects", "ugc_comment", {"their_subject_kinds", "their_subject_flags"}),
        "read_file": ("content", "unclassified", {"kind", "amount_cents", "amount_meaning", "flagged_instructions"}),
    },
    "slack": {},  # Slack has no Readers: the agent sees labeled text
}
READER_FIELDS = SUITE_READER_FIELDS["banking"]


def raw_fields(name: str, suite: str = "banking") -> set[str]:
    """The fields `to_fields` returns for `name`: the manifest's outputs, with a Reader's typed fields swapped back
    for the raw field it reads."""
    expected = set(SUITE_MANIFESTS[suite][name]["output"])
    readers = SUITE_READER_FIELDS[suite]
    if name in readers:
        raw, _, typed = readers[name]
        expected = (expected - typed) | {raw}
    return expected


def load_manifests(directory: Path = MANIFEST_DIR) -> dict[str, dict]:
    """Manifests by AgentDojo tool name (`send_money`), without the suite prefix (`banking.`). The prefix is the
    directory's name."""
    prefix = directory.name + "."
    out = {}
    for path in sorted(directory.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        tool = doc["tool"]
        if not tool.startswith(prefix):
            raise ValueError(f"{path.name}: tool name must start with {prefix!r}")
        out[tool.removeprefix(prefix)] = doc
    return out


def suite_tool_names(suite: str) -> list[str]:
    from agentdojo.task_suite.load_suites import get_suite

    return sorted(t.name for t in get_suite(BENCHMARK_VERSION, suite).tools)


def banking_tool_names() -> list[str]:
    return suite_tool_names("banking")


SUITE_MANIFESTS = {suite: load_manifests(manifest_dir(suite)) for suite in SUITES}
MANIFESTS = SUITE_MANIFESTS["banking"]
for _suite in SUITES:
    _missing = sorted(set(suite_tool_names(_suite)) - set(SUITE_MANIFESTS[_suite]))
    assert not _missing, f"{_suite} tools without a manifest: {_missing}"
_overlap = set(SUITE_MANIFESTS["banking"]) & set(SUITE_MANIFESTS["slack"])
assert not _overlap, f"tool names in both suites (the suite would have to be passed everywhere): {sorted(_overlap)}"


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


def _messages(items) -> dict:
    """A list of Slack `Message`s as parallel arrays. The recipient is left out: it is the channel or inbox that was
    asked for, which the caller already knows."""
    return {"senders": [m.sender for m in items], "bodies": [m.body for m in items]}


def _slack_fields(name: str, result) -> dict:
    if name == "get_channels":
        return {"channels": [str(c) for c in result]}
    if name == "get_users_in_channel":
        return {"users": [str(u) for u in result]}
    if name in ("read_channel_messages", "read_inbox"):
        return _messages(result)
    if name == "get_webpage":
        return {"content": "" if result is None else str(result)}
    # Every writer returns None: the platform's fixed one-value status stands in.
    return {"status": "done"}


def _resolve(tool_name: str, suite: str | None) -> tuple[str, str]:
    """(suite, bare name) for a tool name, with or without a suite prefix, or without one when `suite` says which."""
    for s in SUITES:
        if tool_name.startswith(s + "."):
            return s, tool_name.removeprefix(s + ".")
    if suite is not None:
        return suite, tool_name
    hits = [s for s in SUITES if tool_name in SUITE_MANIFESTS[s]]
    if len(hits) != 1:
        raise KeyError(f"no manifest for tool {tool_name!r}")
    return hits[0], tool_name


def to_fields(tool_name: str, result, env=None, suite: str | None = None) -> dict:
    """Convert the return value of function `tool_name` into its manifest's output fields.

    `tool_name` is the AgentDojo name (`send_money`); a suite prefix (`banking.`, `slack.`) is accepted too, and
    `suite` names the suite when the name is bare (otherwise it is found from the manifests, whose names don't
    overlap). `env` is the environment the function ran on; banking's `get_most_recent_transactions` needs it for
    the user's own IBAN (ValueError without it).
    """
    suite, name = _resolve(tool_name, suite)
    if suite not in SUITE_MANIFESTS or name not in SUITE_MANIFESTS[suite]:
        raise KeyError(f"no {suite} manifest for tool {tool_name!r}")
    if suite == "slack":
        fields = _slack_fields(name, result)
    elif name == "get_most_recent_transactions":
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
    expected = raw_fields(name, suite)
    if set(fields) != expected:
        raise ValueError(f"{name}: converted fields {sorted(fields)} differ from the manifest's {sorted(expected)}")
    return fields
