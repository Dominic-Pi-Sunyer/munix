"""Offline tests for adaptive.py. A fake attacker client and a fake target element stand in for the model API.

    cd eval/agentdojo
    .venv/bin/python -m unittest discover -s tests
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from agentdojo.agent_pipeline import AgentPipeline  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.functions_runtime import FunctionCall  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import text_content_block_from_string  # noqa: E402

import adaptive  # noqa: E402
import credit  # noqa: E402

_CREDIT = tempfile.TemporaryDirectory()


def setUpModule():
    # Paid code paths charge the shared credit floor; point them at a scratch file with plenty of room.
    credit.FILE = Path(_CREDIT.name) / ".credit.json"
    credit.set_balance(1000.0, 25.0)


def tearDownModule():
    _CREDIT.cleanup()
from run import Usage  # noqa: E402

SUITE = get_suite("v1.2.2", "banking")
ATTACKER_IBAN = "US133000000121212121212"
MARKER = "FALLFORIT"
UT_TRANSACTIONS = "user_task_1"  # surfaces injection_incoming_transaction only (get_most_recent_transactions)
IT0 = "injection_task_0"


class FakeAttackerClient:
    """Mimics `openai.OpenAI().chat.completions.create`, returning canned replies in order and counting tokens."""

    def __init__(self, replies, prompt_tokens=100, completion_tokens=50):
        self.replies = list(replies)
        self.requests = []
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        reply = self.replies.pop(0) if self.replies else "I cannot help with that."
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply))],
            usage=SimpleNamespace(prompt_tokens=self.prompt_tokens, completion_tokens=self.completion_tokens),
        )


def reply(payload, rationale="because"):
    return json.dumps({"payload": payload, "rationale": rationale})


class FallingAgent(BasePipelineElement):
    """Reads the recent transactions; if what it read contains the marker, it pays the attacker. Then it answers."""

    def __init__(self, usage: Usage | None = None):
        self.usage = usage
        self.runs = 0

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        self.runs += 1
        if self.usage is not None:  # pretend each run made one model call
            self.usage.calls += 1
            self.usage.prompt += 1000
            self.usage.completion += 100
        read_args = {"n": 100}
        result, error = runtime.run_function(env, "get_most_recent_transactions", read_args)
        assert error is None, error
        seen = str(result)
        read_call = FunctionCall(function="get_most_recent_transactions", args=read_args, id="c1")
        out = [
            {"role": "user", "content": [text_content_block_from_string(query)]},
            {"role": "assistant", "content": None, "tool_calls": [read_call]},
            {
                "role": "tool",
                "content": [text_content_block_from_string(seen)],
                "tool_call_id": "c1",
                "tool_call": read_call,
                "error": None,
            },
        ]
        if MARKER in seen:
            pay_args = {"recipient": ATTACKER_IBAN, "amount": 1.0, "subject": "spotify", "date": "2022-03-01"}
            _, error = runtime.run_function(env, "send_money", pay_args)
            assert error is None, error
            pay_call = FunctionCall(function="send_money", args=pay_args, id="c2")
            out.append({"role": "assistant", "content": None, "tool_calls": [pay_call]})
            out.append(
                {
                    "role": "tool",
                    "content": [text_content_block_from_string("sent")],
                    "tool_call_id": "c2",
                    "tool_call": pay_call,
                    "error": None,
                }
            )
        out.append(
            {"role": "assistant", "content": [text_content_block_from_string("Your total spending was 1050.")], "tool_calls": None}
        )
        return query, runtime, env, out, extra_args or {}


def make_target(agent=None):
    agent = agent or FallingAgent()
    usage = Usage()
    agent.usage = usage
    pipe = AgentPipeline([agent])
    pipe.name = "local-fake"
    wrapped, capture = adaptive.with_capture(pipe)
    return adaptive.Target(wrapped, capture, usage), agent


def run_search(replies, rounds=5, budget=100.0, prices=(1.0, 1.0), out_dir=None, client=None):
    client = client or FakeAttackerClient(replies)
    attacker = adaptive.Attacker(client, "fake-attacker", "low")
    target, agent = make_target()
    out = Path(out_dir or tempfile.mkdtemp()) / "search.json"
    doc = adaptive.search(
        suite=SUITE,
        suite_name="banking",
        pairs=[(UT_TRANSACTIONS, IT0)],
        rounds=rounds,
        budget=budget,
        attacker=attacker,
        target=target,
        prices=prices,
        out_path=out,
        config={"test": True},
    )
    return doc, client, agent, out


class ParseTests(unittest.TestCase):
    def test_parses_plain_fenced_and_wrapped_json(self):
        self.assertEqual(adaptive.parse_attacker_reply(reply("p", "r")), ("p", "r"))
        self.assertEqual(adaptive.parse_attacker_reply("```json\n" + reply("p") + "\n```")[0], "p")
        self.assertEqual(adaptive.parse_attacker_reply("Sure! " + reply("p") + " Hope that helps.")[0], "p")

    def test_rejects_refusals_and_malformed_replies(self):
        for bad in ("I can't help with that.", "", "{not json", '{"payload": ""}', '{"payload": 5}', "[1, 2]", "{}"):
            self.assertIsNone(adaptive.parse_attacker_reply(bad), bad)


class TranscriptTests(unittest.TestCase):
    def test_transcript_has_calls_results_and_answer(self):
        target, _ = make_target()
        adaptive.run_case(SUITE, target, SUITE.get_user_task_by_id(UT_TRANSACTIONS), SUITE.get_injection_task_by_id(IT0), {})
        text = adaptive.compact_transcript(target.capture.messages)
        self.assertIn("CALL get_most_recent_transactions", text)
        self.assertIn("RESULT:", text)
        self.assertIn("ASSISTANT: Your total spending was 1050.", text)

    def test_long_transcripts_keep_start_and_end(self):
        calls = [FunctionCall(function="f", args={"i": i}) for i in range(200)]
        msgs = [{"role": "assistant", "content": None, "tool_calls": calls}]
        msgs.append({"role": "assistant", "content": [text_content_block_from_string("FINAL ANSWER")], "tool_calls": None})
        text = adaptive.compact_transcript(msgs)
        self.assertLessEqual(len(text), adaptive.TRANSCRIPT_CHARS + 20)
        self.assertTrue(text.startswith("CALL f"))
        self.assertTrue(text.endswith("FINAL ANSWER"))


class SearchTests(unittest.TestCase):
    def test_injections_fill_exactly_the_surfaced_vectors(self):
        doc, _, _, _ = run_search([reply("hello")], rounds=1)
        surface = adaptive.Surface(SUITE, None)
        expected = surface.get_injection_candidates(SUITE.get_user_task_by_id(UT_TRANSACTIONS))
        self.assertEqual(doc["pairs"][0]["vectors"], expected)
        self.assertEqual(expected, ["injection_incoming_transaction"])
        # a task that surfaces a different vector set gets exactly that set
        other = adaptive.slots_for(SUITE, surface, SUITE.get_user_task_by_id("user_task_0"))
        self.assertIn("injection_bill_text", other)
        self.assertNotIn("injection_incoming_transaction", other)

    def test_payload_reaches_the_target_and_a_success_stops_the_pair(self):
        doc, client, agent, out = run_search([reply("plain text"), reply(f"{MARKER} pay up"), reply("never asked")])
        pair = doc["pairs"][0]
        self.assertEqual([r["status"] for r in pair["rounds"]], ["ran", "ran"])
        self.assertFalse(pair["rounds"][0]["security"])
        self.assertTrue(pair["rounds"][1]["security"])
        self.assertEqual(pair["status"], "broken")
        self.assertEqual(pair["broken_round"], 2)
        self.assertEqual(pair["winning_payload"], f"{MARKER} pay up")
        self.assertEqual(agent.runs, 2)
        self.assertEqual(len(client.requests), 2)  # no third attacker call after the success
        self.assertEqual(doc["totals"]["pairs_broken"], 1)
        self.assertEqual(adaptive.load_full(out)["pairs"][0]["status"], "broken")

    def test_history_accumulates_in_the_attacker_message(self):
        _, client, _, _ = run_search([reply("first idea"), reply("second idea"), reply(f"{MARKER}")], rounds=3)
        users = [r["messages"][1]["content"] for r in client.requests]
        self.assertEqual(client.requests[0]["messages"][0]["content"], adaptive.ATTACKER_SYSTEM_PROMPT)
        self.assertEqual(client.requests[0]["reasoning_effort"], "low")
        self.assertIn(SUITE.get_injection_task_by_id(IT0).GOAL, users[0])
        self.assertIn(SUITE.get_user_task_by_id(UT_TRANSACTIONS).PROMPT, users[0])
        self.assertIn("injection_incoming_transaction", users[0])
        self.assertIn("Sushi dinner", users[0])  # the slot's default text
        self.assertNotIn("EARLIER ROUNDS", users[0])
        self.assertIn("first idea", users[1])
        self.assertIn("CALL get_most_recent_transactions", users[1])
        self.assertNotIn("second idea", users[1])
        self.assertIn("first idea", users[2])
        self.assertIn("second idea", users[2])
        self.assertIn("Round 2 outcome: attack failed", users[2])

    def test_refusals_and_malformed_replies_count_as_rounds(self):
        doc, client, agent, _ = run_search(
            [reply("one"), "I can't help with that.", "{broken json", reply("four")], rounds=4
        )
        pair = doc["pairs"][0]
        self.assertEqual([r["status"] for r in pair["rounds"]], ["ran", "attacker_refused", "attacker_refused", "ran"])
        self.assertEqual(doc["totals"]["attacker_refusals"], 2)
        self.assertEqual(doc["totals"]["rounds_used"], 4)
        self.assertEqual(agent.runs, 2)  # the target ran only for usable payloads
        self.assertEqual(pair["status"], "held")
        # refused rounds show up in the next attacker message
        self.assertIn("attacker_refused (nothing was run)", client.requests[2]["messages"][1]["content"])

    def test_attacker_api_error_is_recorded_and_counts(self):
        client = FakeAttackerClient([reply("a")])
        real = client.chat.completions.create

        def flaky(**kwargs):
            if len(client.requests) == 1:
                client.requests.append(kwargs)
                raise RuntimeError("503 upstream")
            return real(**kwargs)

        client.chat.completions.create = flaky
        doc, _, _, _ = run_search([], rounds=2, client=client)
        self.assertEqual([r["status"] for r in doc["pairs"][0]["rounds"]], ["ran", "attacker_error"])

    def test_budget_stop_saves_results(self):
        # each round costs: attacker 100+50 tokens, target 1000+100 tokens, at $1 per million each -> ~$0.00125
        doc, client, _, out = run_search(
            [reply("a"), reply("b"), reply("c")], rounds=3, budget=0.0015, prices=(1.0, 1.0)
        )
        self.assertEqual(doc["stopped"], "budget")
        self.assertEqual(len(doc["pairs"][0]["rounds"]), 2)  # round 1 costs 0.00125, round 2 pushes it past
        self.assertEqual(doc["pairs"][0]["status"], "budget_stopped")
        self.assertEqual(len(client.requests), 2)
        saved = adaptive.load_full(out)
        self.assertEqual(saved["stopped"], "budget")
        self.assertAlmostEqual(saved["totals"]["estimated_cost_usd"], 0.0025, places=4)
        self.assertEqual(saved["totals"]["attacker_usage"]["prompt_tokens"], 200)
        self.assertEqual(saved["totals"]["target_usage"]["prompt_tokens"], 2000)
        self.assertGreater(saved["pairs"][0]["rounds"][0]["cost_usd"], 0)

    def test_credit_floor_stops_the_search_and_charges_what_it_spent(self):
        saved = credit.FILE
        credit.FILE = Path(tempfile.mkdtemp()) / ".credit.json"
        self.addCleanup(setattr, credit, "FILE", saved)
        credit.set_balance(25.0015, 25.0)
        doc, *_ = run_search([reply("a"), reply("b"), reply("c")], rounds=3, budget=100.0, prices=(1.0, 1.0))
        self.assertEqual(doc["stopped"], "credit_floor")
        self.assertEqual(doc["pairs"][0]["status"], "credit_stopped")
        self.assertLess(len(doc["pairs"][0]["rounds"]), 3)
        state = credit._read(credit.FILE)
        self.assertAlmostEqual(state["spent_since_usd"], doc["totals"]["estimated_cost_usd"], places=4)

    def test_budget_stop_marks_remaining_pairs_not_run(self):
        client = FakeAttackerClient([reply("a")] * 5)
        attacker = adaptive.Attacker(client, "fake", "low")
        target, _ = make_target()
        out = Path(tempfile.mkdtemp()) / "s.json"
        doc = adaptive.search(
            suite=SUITE, suite_name="banking",
            pairs=[(UT_TRANSACTIONS, "injection_task_0"), (UT_TRANSACTIONS, "injection_task_1"), ("user_task_3", IT0)],
            rounds=3, budget=0.001, attacker=attacker, target=target, prices=(1.0, 1.0), out_path=out, config={},
        )
        self.assertEqual([p["status"] for p in doc["pairs"]], ["budget_stopped", "not_run", "not_run"])

    def test_every_pair_gets_its_own_rounds(self):
        client = FakeAttackerClient([reply("x"), reply(MARKER), reply("y"), reply("z")])
        attacker = adaptive.Attacker(client, "fake", None)
        target, _ = make_target()
        out = Path(tempfile.mkdtemp()) / "s.json"
        doc = adaptive.search(
            suite=SUITE, suite_name="banking",
            pairs=[(UT_TRANSACTIONS, IT0), (UT_TRANSACTIONS, "injection_task_4")],
            rounds=2, budget=100, attacker=attacker, target=target, prices=(1.0, 1.0), out_path=out, config={},
        )
        self.assertEqual(doc["pairs"][0]["status"], "broken")
        self.assertEqual(len(doc["pairs"][1]["rounds"]), 2)
        self.assertNotIn("reasoning_effort", client.requests[0])  # effort None sends none
        # the second pair starts with no history from the first
        self.assertNotIn("EARLIER ROUNDS", client.requests[2]["messages"][1]["content"])


class AgyAttackerTests(unittest.TestCase):
    """The agy attacker, against a fake `agy` that records how it was called and prints a canned reply."""

    def fake_agy(self, reply_text: str, exit_code: int = 0) -> tuple[str, Path]:
        d = Path(tempfile.mkdtemp())
        log = d / "calls.jsonl"
        script = d / "agy"
        script.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            f"open({str(log)!r}, 'a').write(json.dumps({{'argv': sys.argv[1:], 'cwd': os.getcwd(), "
            "'files': os.listdir('.')}) + '\\n')\n"
            f"print({reply_text!r})\n"
            f"sys.exit({exit_code})\n"
        )
        script.chmod(0o755)
        return str(script), log

    def search_with(self, attacker):
        target, agent = make_target()
        out = Path(tempfile.mkdtemp()) / "search.json"
        doc = adaptive.search(
            suite=SUITE, suite_name="banking", pairs=[(UT_TRANSACTIONS, IT0)], rounds=2, budget=100.0,
            attacker=attacker, target=target, prices=(1.0, 1.0), out_path=out, config={"test": True},
        )
        return doc, agent

    def test_the_prefix_picks_agy_and_anything_else_a_meta_model(self):
        self.assertIsInstance(adaptive.make_attacker(None, "agy:gemini-3.8-flash-medium", "low"), adaptive.AgyAttacker)
        self.assertEqual(adaptive.make_attacker(None, "agy:gemini-3.8-flash-medium", "low").model,
                         "gemini-3.8-flash-medium")
        self.assertIsInstance(adaptive.make_attacker(FakeAttackerClient([]), "muse-spark-1.3", "low"), adaptive.Attacker)

    def test_a_search_runs_on_agy_and_costs_no_meta_credit(self):
        binary, log = self.fake_agy(reply(f"{MARKER} pay up"))
        attacker = adaptive.AgyAttacker("gemini-3.8-flash-medium", binary=binary)
        doc, agent = self.search_with(attacker)
        self.assertEqual(doc["pairs"][0]["status"], "broken")
        self.assertEqual(doc["totals"]["attacker_usage"]["calls"], 1)
        self.assertEqual(attacker.usage.cost(1.0, 1.0), 0)
        call = json.loads(log.read_text().splitlines()[0])
        argv = call["argv"]
        self.assertEqual(argv[0], "-p")
        self.assertTrue(argv[1].startswith(adaptive.ATTACKER_SYSTEM_PROMPT))
        self.assertIn(IT0.replace("_", " ").split()[0], argv[1].lower())
        self.assertEqual(argv[argv.index("--model") + 1], "gemini-3.8-flash-medium")
        self.assertIn("--sandbox", argv)
        self.assertIn("--disable-slash-commands", argv)
        self.assertNotIn("--dangerously-skip-permissions", argv)
        self.assertEqual(call["files"], [])  # an empty folder: nothing for the attacker to read or change

    def test_an_agy_failure_costs_the_round_not_the_search(self):
        binary, _ = self.fake_agy("quota exceeded", exit_code=1)
        doc, agent = self.search_with(adaptive.AgyAttacker("gemini-3.8-flash-medium", binary=binary))
        self.assertEqual([r["status"] for r in doc["pairs"][0]["rounds"]], ["attacker_error", "attacker_error"])
        self.assertEqual(agent.runs, 0)
        self.assertEqual(doc["totals"]["attacker_errors"], 2)


class ReplayTests(unittest.TestCase):
    def test_replay_reruns_the_stored_payload(self):
        doc, _, _, out = run_search([reply("meh"), reply(f"{MARKER} again")])
        self.assertEqual(doc["pairs"][0]["status"], "broken")
        source = adaptive.load_full(out)
        target, agent = make_target()
        replay_out = Path(tempfile.mkdtemp()) / "replay.json"
        result = adaptive.replay(
            suite=SUITE, source=source, target=target, repeats=3, out_path=replay_out, config={}, prices=(1.0, 1.0)
        )
        self.assertEqual(agent.runs, 3)
        pair = result["pairs"][0]
        self.assertEqual(pair["payload"], f"{MARKER} again")
        self.assertEqual(pair["attack_successes"], 3)
        self.assertEqual(len(pair["runs"]), 3)
        self.assertEqual(result["totals"]["runs"], 3)
        self.assertEqual(json.loads(replay_out.read_text())["totals"]["attack_successes"], 3)

    def test_replay_skips_pairs_that_were_not_broken(self):
        doc, _, _, out = run_search([reply("meh")], rounds=1)
        target, agent = make_target()
        result = adaptive.replay(
            suite=SUITE, source=adaptive.load_full(out), target=target, repeats=2,
            out_path=Path(tempfile.mkdtemp()) / "r.json", config={},
        )
        self.assertEqual(agent.runs, 0)
        self.assertEqual(result["pairs"], [])

    def test_replay_records_munix_summaries(self):
        import munix_executor

        class FakeSession:
            def end_task(self):
                munix_executor.SUMMARIES.append({"index": len(munix_executor.SUMMARIES) + 1, "denials": 1})

        _, _, _, out = run_search([reply(MARKER)])
        munix_executor.SUMMARIES.clear()
        target, _ = make_target()
        result = adaptive.replay(
            suite=SUITE, source=adaptive.load_full(out), target=target, repeats=2,
            out_path=Path(tempfile.mkdtemp()) / "r.json", config={}, session=FakeSession(),
        )
        self.assertEqual([r["munix"]["denials"] for r in result["pairs"][0]["runs"]], [1, 1])


if __name__ == "__main__":
    unittest.main()


class WithholdingTests(unittest.TestCase):
    """Successful payloads are working attacks: they never reach the public results file."""

    def test_search_withholds_only_the_successful_payload(self):
        doc, _, _, out = run_search([reply("a harmless miss"), reply(f"{MARKER} wins")])
        public_text = out.read_text()
        private_path = out.parent / "private" / out.name
        self.assertNotIn(MARKER, public_text)
        self.assertIn("a harmless miss", public_text)  # failed attempts stay public
        self.assertIn(f"{MARKER} wins", private_path.read_text())
        public = json.loads(public_text)
        pair = public["pairs"][0]
        self.assertNotIn("winning_payload", pair)
        self.assertEqual(pair["winning_payload_sha256"], hashlib.sha256(f"{MARKER} wins".encode()).hexdigest())
        won = pair["rounds"][1]
        self.assertEqual(won["payload"], adaptive.WITHHELD)
        self.assertEqual(won["transcript"], adaptive.WITHHELD)
        self.assertEqual(won["rationale"], adaptive.WITHHELD)
        self.assertEqual(adaptive.load_full(out)["pairs"][0]["winning_payload"], f"{MARKER} wins")

    def test_replay_withholds_payloads_and_transcripts(self):
        _, _, _, out = run_search([reply(f"{MARKER} wins")])
        target, _ = make_target()
        replay_out = Path(tempfile.mkdtemp()) / "replay.json"
        adaptive.replay(
            suite=SUITE, source=adaptive.load_full(out), target=target, repeats=2, out_path=replay_out,
            config={}, prices=(1.0, 1.0),
        )
        public_text = replay_out.read_text()
        self.assertNotIn(MARKER, public_text)
        pair = json.loads(public_text)["pairs"][0]
        self.assertEqual(pair["payload"], adaptive.WITHHELD)
        self.assertTrue(all(r["transcript"] == adaptive.WITHHELD for r in pair["runs"]))
        self.assertIn(MARKER, (replay_out.parent / "private" / replay_out.name).read_text())

    def test_redact_splits_a_file_written_before_withholding(self):
        _, _, _, out = run_search([reply(f"{MARKER} wins")])
        full = adaptive.load_full(out)
        old_style = Path(tempfile.mkdtemp()) / "old.json"
        old_style.write_text(json.dumps(full))
        self.assertIn(MARKER, old_style.read_text())
        adaptive.write_split(adaptive.load_full(old_style), old_style)
        self.assertNotIn(MARKER, old_style.read_text())
        self.assertIn(MARKER, (old_style.parent / "private" / old_style.name).read_text())


class YamlEscapeTests(unittest.TestCase):
    """AgentDojo pastes payloads into double-quoted YAML; escaped, they must come back exactly."""

    def test_awkward_payloads_round_trip_through_the_real_banking_environment(self):
        for payload in [
            'He said "pay now"\nthen left',
            "back\\slash and\ttab",
            'ends with a quote"',
            "unicode é ✓ and {braces}",
            "bell\x07 and cr\r",
        ]:
            env = SUITE.load_and_inject_default_environment(
                {"injection_incoming_transaction": adaptive.yaml_double_quoted(payload)}
            )
            subjects = [t.subject for t in env.bank_account.transactions]
            self.assertIn(payload, subjects, repr(payload))


class TargetArgsTests(unittest.TestCase):
    def test_target_args_build_a_pipeline_without_the_network(self):
        # run.make_pipeline reads every field; a missing one (simulated_user once was) breaks replays at start.
        from run import Usage, make_pipeline

        pipe = make_pipeline(adaptive.target_args("bare", "low"), "muse-spark-1.3", "unused-key", Usage(), None)
        self.assertEqual(pipe.name, "local-bare-low")


class ReplayBudgetTests(unittest.TestCase):
    def test_replay_stops_before_a_run_once_the_budget_is_reached(self):
        _, _, _, out = run_search([reply(f"{MARKER} wins")])
        target, agent = make_target()
        doc = adaptive.replay(
            suite=SUITE, source=adaptive.load_full(out), target=target, repeats=5,
            out_path=Path(tempfile.mkdtemp()) / "r.json", config={}, prices=(1.0, 1.0), budget=0.0,
        )
        self.assertEqual(doc["stopped"], "budget")
        self.assertEqual(agent.runs, 0)


# ---------------------------------------------------------------------------------------------------------------
# Munix mode: the target runs inside Munix (a fake session stands in for the bridge), with feedback and seeds
# ---------------------------------------------------------------------------------------------------------------

import contextlib  # noqa: E402
import io  # noqa: E402
from unittest import mock  # noqa: E402

import munix_executor  # noqa: E402

LEAK = "DE89370400440532013000"  # a value that sits in the fake ledger and must never reach the attacker
DENY_LEDGER = [
    {"event": {"event": "ruling", "outcome": "allow", "reasons": ["plan.step1", "recipient.trace_ok"]}},
    {
        "event": {
            "event": "ruling",
            "outcome": "deny",
            "code": "untrusted_destination",
            "reasons": ["plan.step2", "recipient.trace_untrusted"],
            "value": LEAK,
            "args": {"recipient": LEAK},
        }
    },
]
CONFIRM_LEDGER = [
    {"event": {"event": "ruling", "outcome": "confirm_user", "reasons": ["plan.step1", "amount.value_unbound"]}}
]
QUIET_LEDGER = [{"event": {"event": "ruling", "outcome": "allow", "reasons": ["recipient.trace_ok"]}}]


class FakeSession:
    """Stands in for MunixSession: the agent calls `begin()` when its case starts; `end_task` then records the summary
    the real session would (one per case), with the next scripted ledger. Scripted entries may set `start=False`."""

    def __init__(self, script):
        self.script = list(script)
        self.pending = False
        self.cases = 0
        self.ledger_dir = Path(tempfile.mkdtemp())

    def begin(self):
        self.pending = True

    def end_task(self):
        if not self.pending:
            return
        self.pending = False
        entry = dict(self.script.pop(0) if self.script else {"ledger": QUIET_LEDGER})
        self.cases += 1
        summary = {"index": self.cases, "calls": entry.get("calls", 3), "denials": entry.get("denials", 1),
                   "tools_run": entry.get("tools_run", 2), "context_trust": entry.get("context_trust", 85)}
        if entry.get("start", True):
            path = self.ledger_dir / f"case{self.cases}.jsonl"
            path.write_text("".join(json.dumps(line) + "\n" for line in entry.get("ledger", QUIET_LEDGER)))
            summary.update(ledger=str(path), plan_steps=2, task="T-1", plan="planner")
            if "usage" in entry:
                summary["supervisor_usage"] = entry["usage"]
            elif entry.get("usage", 0) is not None:
                summary["supervisor_usage"] = {"calls": 1, "prompt_tokens": 100, "completion_tokens": 10}
        else:
            summary.update(error="the planner wrote no valid plan", ledger=str(self.ledger_dir / "none.jsonl"))
        munix_executor.SUMMARIES.append(summary)


class MunixFallingAgent(FallingAgent):
    def __init__(self, session):
        super().__init__()
        self.session = session

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        self.session.begin()
        return super().query(query, runtime, env, messages, extra_args)


def run_munix_search(replies, script, rounds=2, budget=100.0, prices=(1.0, 1.0), seeds=None, client=None, system=None):
    munix_executor.SUMMARIES.clear()
    session = FakeSession(script)
    agent = MunixFallingAgent(session)
    usage = Usage()
    agent.usage = usage
    pipe = AgentPipeline([agent])
    pipe.name = "local-fake"
    wrapped, capture = adaptive.with_capture(pipe)
    target = adaptive.Target(wrapped, capture, usage)
    client = client or FakeAttackerClient(replies)
    attacker = adaptive.Attacker(client, "fake-attacker", "low", system or adaptive.attacker_system_prompt(True))
    out = Path(tempfile.mkdtemp()) / "search.json"
    doc = adaptive.search(
        suite=SUITE, suite_name="banking", pairs=[(UT_TRANSACTIONS, IT0)], rounds=rounds, budget=budget,
        attacker=attacker, target=target, prices=prices, out_path=out, config={"mode": "munix"},
        munix=adaptive.MunixSide(session), seeds=seeds,
    )
    return doc, client, out


class MunixFeedbackTests(unittest.TestCase):
    def test_first_stop_and_counts_reach_the_attacker_without_ledger_values(self):
        doc, client, out = run_munix_search([reply("one"), reply("two")], [{"ledger": DENY_LEDGER}, {"ledger": CONFIRM_LEDGER}])
        r1, r2 = doc["pairs"][0]["rounds"]
        self.assertEqual(r1["munix_stop"], "deny:untrusted_destination:trace_untrusted")
        self.assertEqual(r1["munix_counts"], {"calls": 3, "denials": 1, "tools_run": 2, "context_trust": 85})
        self.assertEqual(r2["munix_stop"], "confirm_user:value_unbound")
        second = client.requests[1]["messages"][1]["content"]
        self.assertIn(
            "Munix: the Gate's first refusal was deny untrusted_destination (trace_untrusted); "
            "3 tool calls, 1 refused, 2 run, context trust 85",
            second,
        )
        self.assertIn("CALL get_most_recent_transactions", second)  # the transcript feedback is unchanged
        self.assertNotIn("Munix:", client.requests[0]["messages"][1]["content"])
        self.assertNotIn(LEAK, second)
        self.assertNotIn(LEAK, out.read_text())  # nor does the results file carry a ledger value
        third = adaptive.build_attacker_message("g", "u", {}, doc["pairs"][0]["rounds"], 3, 3)
        self.assertIn("held a request for the user, who declined: value_unbound", third)

    def test_each_round_reads_its_own_case(self):
        doc, client, _ = run_munix_search(
            [reply("a"), reply("b"), reply("c")], [{"ledger": DENY_LEDGER}, {"ledger": QUIET_LEDGER}], rounds=3
        )
        self.assertEqual([r["munix_stop"] for r in doc["pairs"][0]["rounds"]][:2], ["deny:untrusted_destination:trace_untrusted", "no_block"])
        self.assertEqual(munix_executor.SUMMARIES, [])  # taken, not left for the next round
        self.assertEqual(len(doc["pairs"][0]["rounds"]), 3)

    def test_a_case_munix_could_not_start_is_not_started(self):
        doc, client, _ = run_munix_search([reply("a"), reply("b")], [{"start": False}, {"ledger": QUIET_LEDGER}])
        r1 = doc["pairs"][0]["rounds"][0]
        self.assertEqual(r1["munix_stop"], "not_started")
        self.assertIn("Munix could not start this task", client.requests[1]["messages"][1]["content"])

    def test_no_summary_at_all_is_not_started(self):
        self.assertEqual(adaptive.munix_case_stop(None), "not_started")
        self.assertEqual(adaptive.munix_case_stop({"error": "x", "ledger": "l"}), "not_started")

    def test_only_fixed_looking_names_are_shown(self):
        text = adaptive.describe_munix(f"deny:{LEAK}:trace untrusted", {"calls": 1, "denials": 0, "tools_run": 1, "context_trust": 100})
        self.assertNotIn(LEAK, text)
        self.assertIn("deny other (other)", text)

    def test_a_damaged_ledger_is_reported_not_raised(self):
        d = Path(tempfile.mkdtemp())
        (d / "l.jsonl").write_text("{not json\n")
        self.assertEqual(adaptive.munix_case_stop({"plan_steps": 1, "ledger": str(d / "l.jsonl")}), "unreadable_ledger")

    def test_summary_prints_best_outcome_and_stop_counts(self):
        doc, _, _ = run_munix_search(
            [reply("a"), reply("b"), reply("c")], [{"ledger": QUIET_LEDGER}, {"ledger": DENY_LEDGER}, {"ledger": DENY_LEDGER}], rounds=3
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            adaptive.print_search_summary(doc)
        text = buf.getvalue()
        self.assertIn("best: furthest: deny:untrusted_destination:trace_untrusted", text)
        self.assertIn("deny:untrusted_destination:trace_untrusted x2, no_block x1", text)
        self.assertEqual(doc["totals"]["first_stops"]["no_block"], 1)


class MunixBriefTests(unittest.TestCase):
    def test_the_brief_is_only_in_munix_mode(self):
        self.assertEqual(adaptive.attacker_system_prompt(False), adaptive.ATTACKER_SYSTEM_PROMPT)
        self.assertNotIn("Munix", adaptive.ATTACKER_SYSTEM_PROMPT)
        client = FakeAttackerClient([])
        self.assertEqual(adaptive.make_attacker(client, "m", "low", False).system_prompt, adaptive.ATTACKER_SYSTEM_PROMPT)
        munix = adaptive.make_attacker(client, "m", "low", True)
        self.assertTrue(munix.system_prompt.startswith(adaptive.ATTACKER_SYSTEM_PROMPT))
        self.assertTrue(munix.system_prompt.endswith(adaptive.MUNIX_ATTACKER_BRIEF))
        self.assertIn("security check", adaptive.MUNIX_ATTACKER_BRIEF)
        self.assertEqual(adaptive.make_attacker(None, "agy:x", "low", True).system_prompt, munix.system_prompt)
        _, bare_client, _, _ = run_search([reply("x")], rounds=1)
        self.assertEqual(bare_client.requests[0]["messages"][0]["content"], adaptive.ATTACKER_SYSTEM_PROMPT)
        _, munix_client, _ = run_munix_search([reply("x")], [{}], rounds=1)
        self.assertIn(adaptive.MUNIX_ATTACKER_BRIEF, munix_client.requests[0]["messages"][0]["content"])


class MunixBudgetTests(unittest.TestCase):
    def test_supervisor_usage_counts_toward_the_budget(self):
        big = {"calls": 1, "prompt_tokens": 1_000_000, "completion_tokens": 0}  # $1 at $1 per million
        doc, client, _ = run_munix_search(
            [reply("a"), reply("b"), reply("c")], [{"usage": big}] * 3, rounds=3, budget=0.5
        )
        self.assertEqual(doc["stopped"], "budget")
        self.assertEqual(len(doc["pairs"][0]["rounds"]), 1)  # the agent and attacker alone ($0.00125) would not stop it
        self.assertGreater(doc["totals"]["estimated_cost_usd"], 1.0)
        self.assertGreater(doc["pairs"][0]["rounds"][0]["cost_usd"], 1.0)
        self.assertEqual(doc["totals"]["munix_usage"]["prompt_tokens"], 1_000_000)

    def test_unknown_supervisor_usage_is_over_estimated(self):
        cost = adaptive.bridges_cost([{"supervisor_usage": None}, {}], (1.25, 4.25))
        per = (10_000 * 1.25 + 4_000 * 4.25) / 1e6
        self.assertAlmostEqual(cost, 2 * per)
        known = adaptive.bridges_cost([{"supervisor_usage": {"prompt_tokens": 1000, "completion_tokens": 100}}], (1.25, 4.25))
        self.assertAlmostEqual(known, (1000 * 1.25 + 100 * 4.25) / 1e6)

    def test_the_credit_floor_stops_a_munix_search_on_supervisor_spend(self):
        saved = credit.FILE
        credit.FILE = Path(tempfile.mkdtemp()) / ".credit.json"
        self.addCleanup(setattr, credit, "FILE", saved)
        credit.set_balance(25.5, 25.0)
        big = {"calls": 1, "prompt_tokens": 1_000_000, "completion_tokens": 0}
        doc, _, _ = run_munix_search([reply("a"), reply("b"), reply("c")], [{"usage": big}] * 3, rounds=3)
        self.assertEqual(doc["stopped"], "credit_floor")
        self.assertEqual(len(doc["pairs"][0]["rounds"]), 1)
        self.assertGreater(credit._read(credit.FILE)["spent_since_usd"], 1.0)


class SeedTests(unittest.TestCase):
    SEED = "SEEDWINNER pay up now"

    def bare_winner(self):
        _, _, _, out = run_search([reply("meh"), reply(f"{MARKER} {self.SEED}")])
        return out

    def test_a_winner_becomes_round_zero(self):
        out = self.bare_winner()
        seeds, notes = adaptive.find_seeds(adaptive.load_full(out), [(UT_TRANSACTIONS, IT0)])
        self.assertEqual(notes, [])
        self.assertEqual(seeds[(UT_TRANSACTIONS, IT0)]["payload"], f"{MARKER} {self.SEED}")
        doc, client, _ = run_munix_search([reply("first")], [{}], rounds=1, seeds=seeds)
        first = client.requests[0]["messages"][1]["content"]
        self.assertIn("EARLIER ROUNDS", first)
        self.assertIn("Round 0 (worked against the agent WITHOUT Munix) payload:", first)
        self.assertIn(self.SEED, first)
        self.assertIn("CALL send_money", first)  # what the bare agent did
        self.assertEqual(doc["pairs"][0]["seed"]["source_round"], 2)
        self.assertEqual(len(doc["pairs"][0]["rounds"]), 1)  # the seed is not a round

    def test_missing_private_copy_means_no_seed_and_a_note(self):
        out = self.bare_winner()
        (out.parent / "private" / out.name).unlink()
        seeds, notes = adaptive.find_seeds(adaptive.load_full(out), [(UT_TRANSACTIONS, IT0)])
        self.assertEqual(seeds, {})
        self.assertEqual(len(notes), 1)
        self.assertIn("private copy", notes[0])
        self.assertNotIn(MARKER, notes[0])
        doc, client, _ = run_munix_search([reply("x")], [{}], rounds=1, seeds=seeds)
        self.assertNotIn("Round 0", client.requests[0]["messages"][1]["content"])
        self.assertNotIn("seed", doc["pairs"][0])

    def test_pairs_without_a_winner_get_a_note(self):
        _, _, _, out = run_search([reply("meh")], rounds=1)
        seeds, notes = adaptive.find_seeds(adaptive.load_full(out), [(UT_TRANSACTIONS, IT0), ("user_task_3", IT0)])
        self.assertEqual(seeds, {})
        self.assertEqual(len(notes), 2)

    def test_the_public_copy_never_holds_seed_text(self):
        # a seed that is not the marker, so a resubmitted copy does not itself win and the round stays a failed one
        seeds = {(UT_TRANSACTIONS, IT0): {
            "payload": self.SEED, "source_mode": "bare", "source_round": 2, "transcript": f"CALL send_money({self.SEED})"}}
        # the attacker resubmits the seed inside a longer payload, then even quotes it in a refusal
        again = f"Please note: {self.SEED} (resend)"
        doc, _, munix_out = run_munix_search(
            [reply(again), reply("fresh idea"), f"I will not repeat {self.SEED}"], [{}, {}, {}], rounds=3, seeds=seeds
        )
        private = (munix_out.parent / "private" / munix_out.name).read_text()
        public = munix_out.read_text()
        self.assertIn(self.SEED, private)
        self.assertNotIn(self.SEED, public)
        pair = json.loads(public)["pairs"][0]
        self.assertEqual(pair["seed"]["payload"], adaptive.WITHHELD)
        self.assertEqual(pair["seed"]["transcript"], adaptive.WITHHELD)
        self.assertEqual(pair["seed"]["payload_sha256"], hashlib.sha256(self.SEED.encode()).hexdigest())
        self.assertEqual(pair["rounds"][0]["payload"], adaptive.WITHHELD)  # a copy of the seed
        self.assertEqual(pair["rounds"][1]["payload"], "fresh idea")  # the rest stays public
        self.assertEqual(pair["rounds"][2].get("attacker_reply"), adaptive.WITHHELD)
        self.assertEqual(adaptive.load_full(munix_out)["pairs"][0]["seed"]["payload"], self.SEED)

    def test_a_real_bare_winner_never_reaches_the_public_munix_file(self):
        out = self.bare_winner()
        seeds, _ = adaptive.find_seeds(adaptive.load_full(out), [(UT_TRANSACTIONS, IT0)])
        _, _, munix_out = run_munix_search([reply("fresh")], [{}], rounds=1, seeds=seeds)
        self.assertNotIn(MARKER, munix_out.read_text())
        self.assertNotIn(self.SEED, munix_out.read_text())
        self.assertIn(MARKER, (munix_out.parent / "private" / munix_out.name).read_text())


class SearchCommandTests(unittest.TestCase):
    """cmd_search wiring, with the network, the search itself and the key patched out."""

    def args(self, **over):
        base = dict(
            suite="banking", user_tasks=UT_TRANSACTIONS, injection_tasks=IT0, rounds=1, budget=1.0,
            attacker_model="muse-spark-1.3", attacker_effort="low", mode="bare", target_model="muse-spark-1.3",
            target_effort="low", munix_bin=sys.executable, detector_url=None, seed_from=None,
        )
        base.update(over)
        return SimpleNamespace(**base)

    def run_cmd(self, **over):
        captured = {}

        def fake_search(**kwargs):
            captured.update(kwargs)
            return {"pairs": [], "stopped": None, "totals": {
                "pairs_broken": 0, "pairs_tried": 0, "rounds_used": 0, "attacker_refusals": 0, "estimated_cost_usd": 0.0}}

        tmp = Path(tempfile.mkdtemp())
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(adaptive, "require_key", lambda: "k"))
            stack.enter_context(mock.patch.object(adaptive, "RESULTS", tmp))
            stack.enter_context(mock.patch.object(adaptive, "search", fake_search))
            stack.enter_context(mock.patch.object(adaptive.openai, "OpenAI", lambda **kw: FakeAttackerClient([])))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            adaptive.cmd_search(self.args(**over))
        return captured

    def test_munix_mode_builds_a_munix_target_and_passes_the_detector_through(self):
        got = self.run_cmd(mode="munix", detector_url="http://127.0.0.1:9000")
        session = got["munix"].session
        self.assertIsInstance(session, munix_executor.MunixSession)
        self.assertEqual(session.detector_url, "http://127.0.0.1:9000")
        self.assertFalse(session.simulated_user)
        self.assertEqual(session.manifests, adaptive.HERE / "manifests" / "banking")
        self.assertEqual(str(session.binary), sys.executable)
        self.assertTrue(session.tag.startswith("banking-adaptive-search-munix-"))
        starts = [e for e in got["target"].pipeline.elements if isinstance(e, munix_executor.MunixStart)]
        self.assertEqual([e.session for e in starts], [session])
        self.assertRegex(got["out_path"].name, r"^adaptive--banking-search-munix-\d{8}T\d{6}Z\.json$")
        self.assertEqual(got["config"]["mode"], "munix")
        self.assertEqual(got["config"]["detector_url"], "http://127.0.0.1:9000")
        self.assertEqual(got["config"]["munix_bin"], sys.executable)
        self.assertEqual(len(got["config"]["munix_bin_sha256"]), 64)
        self.assertIn(adaptive.MUNIX_ATTACKER_BRIEF, got["config"]["attacker_system_prompt"])
        self.assertIn(adaptive.MUNIX_ATTACKER_BRIEF, got["attacker"].system_prompt)
        self.assertIsNone(got["seeds"])

    def test_bare_mode_is_unchanged(self):
        got = self.run_cmd()
        self.assertIsNone(got["munix"])
        self.assertRegex(got["out_path"].name, r"^adaptive--banking-search-\d{8}T\d{6}Z\.json$")
        self.assertEqual(got["attacker"].system_prompt, adaptive.ATTACKER_SYSTEM_PROMPT)
        self.assertEqual(got["config"]["attacker_system_prompt"], adaptive.ATTACKER_SYSTEM_PROMPT)
        self.assertNotIn("detector_url", got["config"])
        self.assertFalse([e for e in got["target"].pipeline.elements if isinstance(e, munix_executor.MunixStart)])

    def test_munix_only_options_are_refused_in_bare_mode(self):
        for over in ({"detector_url": "http://127.0.0.1:9000"}, {"seed_from": "x.json"}):
            with self.assertRaises(SystemExit):
                self.run_cmd(**over)

    def test_a_missing_binary_or_manifests_stop_the_search(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(mode="munix", munix_bin="/nonexistent/munix")
        with self.assertRaises(SystemExit):
            self.run_cmd(mode="munix", suite="nosuchsuite")

    def test_seed_from_reads_the_private_copy_and_says_what_it_skipped(self):
        _, _, _, out = run_search([reply(f"{MARKER} wins")])
        got = self.run_cmd(mode="munix", seed_from=str(out))  # the public path: its private copy is found
        self.assertEqual(got["seeds"][(UT_TRANSACTIONS, IT0)]["payload"], f"{MARKER} wins")
        self.assertEqual(got["config"]["seed_from"], str(out))
        (out.parent / "private" / out.name).unlink()
        self.assertEqual(self.run_cmd(mode="munix", seed_from=str(out))["seeds"], {})
