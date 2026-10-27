"""Offline tests for the Python side of the Munix AgentDojo harness. No model API, no real bridge.

    cd eval/agentdojo
    .venv/bin/python -m unittest discover -s tests
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import yaml  # noqa: E402
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

import convert  # noqa: E402
import munix_executor as mx  # noqa: E402

FAKE = [sys.executable, str(HERE / "fake_bridge.py")]
SUITE = get_suite("v1.2.2", "banking")
IBAN = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TYPES = {"text", "iban", "number", "int", "bool", "date"}
TYPES |= {t + "[]" for t in TYPES}
ROLES = {"destination", "content", "selector", "control"}
REGIONS = {"user_content", "operator_content", "ugc_comment", "unclassified"}
CONFIDENTIAL = {"public", "internal", "private", "secret"}

# Arguments that exercise every banking function once, in an order that works on the default environment.
SAMPLE_CALLS = {
    "get_iban": {},
    "get_balance": {},
    "get_user_info": {},
    "get_scheduled_transactions": {},
    "get_most_recent_transactions": {"n": 100},
    "read_file": {"file_path": "landlord-notices.txt"},
    "send_money": {"recipient": "CH9300762011623852957", "amount": 12.5, "subject": "Lunch", "date": "2022-04-02"},
    "schedule_transaction": {
        "recipient": "GB29NWBK60161331926819",
        "amount": 20.0,
        "subject": "Gym",
        "date": "2022-05-01",
        "recurring": True,
    },
    "update_scheduled_transaction": {"id": 7, "amount": 1200.0},
    "update_user_info": {"city": "Oakland"},
    "update_password": {"password": "new-secret-1"},
}


def new_env():
    return SUITE.load_and_inject_default_environment({})


def runtime():
    return FunctionsRuntime(SUITE.tools)


def assistant_with(*calls: tuple[str, dict]) -> list:
    tool_calls = [FunctionCall(function=f, args=dict(a), id=f"call_{i}") for i, (f, a) in enumerate(calls)]
    return [{"role": "assistant", "content": None, "tool_calls": tool_calls}]


class ConvertTest(unittest.TestCase):
    def test_every_tool_has_a_manifest_and_a_sample(self):
        names = {t.name for t in SUITE.tools}
        self.assertEqual(names, set(convert.MANIFESTS))
        self.assertEqual(names, set(SAMPLE_CALLS))

    def test_to_fields_matches_manifest_outputs(self):
        env, rt = new_env(), runtime()
        for name, args in SAMPLE_CALLS.items():
            with self.subTest(tool=name):
                result, error = rt.run_function(env, name, args)
                self.assertIsNone(error)
                fields = convert.to_fields(name, result)
                self.assertEqual(set(fields), set(convert.MANIFESTS[name]["output"]))
                self.assertEqual(fields, convert.to_fields("banking." + name, result))
                json.dumps(fields)  # plain JSON values only
                lists = [v for v in fields.values() if isinstance(v, list)]
                self.assertEqual(len({len(v) for v in lists}), 1 if lists else 0)

    def test_transactions_are_parallel_arrays_with_real_counterparties(self):
        env, rt = new_env(), runtime()
        for name in ("get_most_recent_transactions", "get_scheduled_transactions"):
            with self.subTest(tool=name):
                result, _ = rt.run_function(env, name, {})
                fields = convert.to_fields(name, result)
                self.assertEqual(len(fields["ids"]), len(result))
                self.assertGreater(len(result), 0)
                for iban in fields["counterparties"]:
                    self.assertNotEqual(iban, "me")
                    self.assertRegex(iban, IBAN)
                for date in fields["dates"]:
                    self.assertRegex(date, DATE)
                self.assertTrue(all(isinstance(a, float) for a in fields["amounts"]))
        recent, _ = rt.run_function(env, "get_most_recent_transactions", {})
        fields = convert.to_fields("get_most_recent_transactions", recent)
        # transaction 5 is the incoming payment: the counterparty is its sender
        i = fields["ids"].index(5)
        self.assertFalse(fields["sent_by_me"][i])
        self.assertEqual(fields["counterparties"][i], "GB29NWBK60161331926819")
        self.assertTrue(fields["sent_by_me"][0])
        self.assertEqual(fields["counterparties"][0], "CH9300762011623852957")

    def test_values(self):
        env, rt = new_env(), runtime()
        self.assertEqual(convert.to_fields("get_balance", rt.run_function(env, "get_balance", {})[0]), {"balance": 1810.0})
        self.assertEqual(
            convert.to_fields("get_iban", rt.run_function(env, "get_iban", {})[0]), {"iban": "DE89370400440532013000"}
        )
        sent = rt.run_function(env, "send_money", SAMPLE_CALLS["send_money"])[0]
        self.assertEqual(
            convert.to_fields("send_money", sent)["message"], "Transaction to CH9300762011623852957 for 12.5 sent."
        )


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.functions = {f.name: f for f in SUITE.tools}

    def test_manifests_parse_and_follow_the_rules(self):
        files = sorted(convert.MANIFEST_DIR.glob("*.yaml"))
        self.assertEqual(len(files), 11)
        tiers = {
            "get_iban": 0, "get_balance": 0, "get_user_info": 0, "get_scheduled_transactions": 0,
            "get_most_recent_transactions": 0, "read_file": 0, "update_user_info": 2, "send_money": 3,
            "schedule_transaction": 3, "update_scheduled_transaction": 3, "update_password": 3,
        }  # fmt: skip
        egress = {"send_money", "schedule_transaction", "update_scheduled_transaction"}
        for path in files:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            name = path.stem
            with self.subTest(manifest=name):
                self.assertEqual(path.read_text(encoding="utf-8").splitlines()[0][:1], "#")
                self.assertEqual(set(doc), {"tool", "description", "tier", "egress", "args", "output"})
                self.assertEqual(doc["tool"], f"banking.{name}")
                self.assertTrue(doc["description"].isascii() and doc["description"].endswith("."))
                self.assertEqual(doc["tier"], tiers[name])
                self.assertEqual(doc["egress"], name in egress)
                self.assertTrue(doc["output"])
                for spec in doc["args"].values():
                    self.assertIn(spec["type"], TYPES)
                    self.assertIn(spec["role"], ROLES)
                for field, spec in doc["output"].items():
                    self.assertRegex(field, r"^[a-z_]{1,32}$")
                    self.assertIn(spec["type"], TYPES)
                    self.assertIn(spec["region"], REGIONS)
                    self.assertIn(spec["confidential"], CONFIDENTIAL)

    def test_args_match_the_function_signature(self):
        for name, doc in convert.MANIFESTS.items():
            with self.subTest(tool=name):
                fields = self.functions[name].parameters.model_fields
                self.assertEqual(set(doc["args"]), set(fields))
                for arg, spec in doc["args"].items():
                    self.assertEqual(bool(spec.get("optional")), not fields[arg].is_required(), arg)

    def test_destinations_are_ibans_and_dates_are_dates(self):
        for name, doc in convert.MANIFESTS.items():
            for arg, spec in doc["args"].items():
                if spec["role"] == "destination":
                    self.assertEqual(spec["type"], "iban", (name, arg))
                if arg == "date":
                    self.assertEqual(spec["type"], "date", (name, arg))

    def test_untrusted_regions(self):
        recent = convert.MANIFESTS["get_most_recent_transactions"]["output"]
        self.assertEqual(recent["subjects"]["region"], "ugc_comment")
        self.assertEqual(convert.MANIFESTS["read_file"]["output"]["content"]["region"], "unclassified")
        for field in ("ids", "counterparties", "sent_by_me", "amounts", "dates", "recurring"):
            self.assertEqual(recent[field]["region"], "operator_content")


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        mx.SUMMARIES.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def session(self, **env):
        s = mx.MunixSession(ledger_dir=self.tmp.name, tag="t", binary=FAKE, read_timeout=20, env=env or None)
        self.addCleanup(s.close)
        return s

    def run_calls(self, session, env, *calls):
        rt = runtime()
        mx.MunixStart(session).query("Pay the bill", rt, env, [], {})
        _, _, _, messages, _ = mx.MunixToolsExecutor(session).query("Pay the bill", rt, env, assistant_with(*calls), {})
        return messages[1:]

    def test_allowed_send_money_changes_the_environment(self):
        env, s = new_env(), self.session()
        before = len(env.bank_account.transactions)
        (msg,) = self.run_calls(s, env, ("send_money", SAMPLE_CALLS["send_money"]))
        self.assertEqual(len(env.bank_account.transactions), before + 1)
        sent = env.bank_account.transactions[-1]
        self.assertEqual((sent.recipient, sent.amount, sent.subject), ("CH9300762011623852957", 12.5, "Lunch"))
        self.assertIsNone(msg["error"])
        self.assertEqual(msg["role"], "tool")
        self.assertEqual(msg["tool_call_id"], "call_0")
        self.assertEqual(
            json.loads(msg["content"][0]["content"]),
            {"message": "Transaction to CH9300762011623852957 for 12.5 sent."},
        )

    def test_read_result_is_the_bridges_text(self):
        env, s = new_env(), self.session()
        (msg,) = self.run_calls(s, env, ("get_most_recent_transactions", {"n": 2}))
        fields = json.loads(msg["content"][0]["content"])
        self.assertEqual(fields["ids"], [4, 5])
        self.assertEqual(fields["sent_by_me"], [True, False])

    def test_denied_call_is_an_error_and_changes_nothing(self):
        env, s = new_env(), self.session(MUNIX_FAKE_DENY="send_money")
        before = env.model_copy(deep=True)
        msg1, msg2 = self.run_calls(
            s, env, ("send_money", SAMPLE_CALLS["send_money"]), ("get_balance", {})
        )
        self.assertEqual(msg1["error"], "denied: policy")
        self.assertEqual(msg1["content"][0]["content"], "")
        self.assertEqual(env, before)
        self.assertIsNone(msg2["error"])  # the denial does not stop the next call
        s.close()
        (summary,) = mx.SUMMARIES
        self.assertEqual((summary["calls"], summary["denials"], summary["tools_run"]), (2, 1, 1))

    def test_function_error_becomes_a_tool_error(self):
        env, s = new_env(), self.session()
        (msg,) = self.run_calls(s, env, ("update_scheduled_transaction", {"id": 999, "amount": 1.0}))
        self.assertIn("not found", msg["error"])
        self.assertEqual(msg["content"][0]["content"], "")

    def test_unknown_tool_never_reaches_the_bridge(self):
        env, s = new_env(), self.session()
        (msg,) = self.run_calls(s, env, ("nope", {}))
        self.assertEqual(msg["error"], "Invalid tool nope provided.")
        s.close()
        self.assertEqual(mx.SUMMARIES[0]["calls"], 0)

    def test_null_arguments_are_dropped(self):
        env, s = new_env(), self.session()
        (msg,) = self.run_calls(s, env, ("update_user_info", {"first_name": None, "city": "Oakland"}))
        self.assertIsNone(msg["error"])
        self.assertEqual(env.user_account.city, "Oakland")
        self.assertEqual(env.user_account.first_name, "Emma")


class StartTest(unittest.TestCase):
    def setUp(self):
        mx.SUMMARIES.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_each_task_gets_a_fresh_bridge_and_records_the_previous_summary(self):
        s = mx.MunixSession(ledger_dir=self.tmp.name, tag="t", binary=FAKE, read_timeout=20)
        self.addCleanup(s.close)
        start, rt, env = mx.MunixStart(s), runtime(), new_env()
        start.query("first task", rt, env, [], {})
        first = s.client
        mx.MunixToolsExecutor(s).query("first task", rt, env, assistant_with(("get_balance", {})), {})
        self.assertEqual(mx.SUMMARIES, [])
        start.query("second task", rt, env, [], {})
        self.assertIsNot(s.client, first)
        self.assertIsNotNone(first._proc.poll())  # the first bridge has exited
        (one,) = mx.SUMMARIES
        self.assertEqual(one["calls"], 1)
        self.assertEqual(one["denials"], 0)
        self.assertEqual(one["context_trust"], 100)
        self.assertTrue(one["ledger_verified"])
        self.assertIsNone(one["takeover"])
        self.assertEqual(one["ledger_entries"], 2)  # start + call
        self.assertEqual(len(one["prompt_sha256"]), 16)
        s.close()
        one, two = mx.SUMMARIES
        self.assertNotEqual(one["prompt_sha256"], two["prompt_sha256"])
        self.assertNotEqual(one["ledger"], two["ledger"])
        self.assertNotEqual(one["task"], two["task"])  # a different process each time
        self.assertEqual(two["calls"], 0)
        self.assertTrue(Path(one["ledger"]).is_file() and Path(two["ledger"]).is_file())

    def test_executor_without_a_started_task_fails_loudly(self):
        s = mx.MunixSession(ledger_dir=self.tmp.name, binary=FAKE)
        with self.assertRaises(mx.BridgeError):
            mx.MunixToolsExecutor(s).query("q", runtime(), new_env(), assistant_with(("get_balance", {})), {})


class BridgeFailureTest(unittest.TestCase):
    def setUp(self):
        mx.SUMMARIES.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def client(self, binary, **kw):
        return mx.BridgeClient(Path("manifests"), Path(self.tmp.name) / "l.jsonl", binary, **kw)

    def test_missing_binary(self):
        with self.assertRaises(mx.BridgeError) as cm:
            self.client(Path(self.tmp.name) / "no-such-munix").start("p")
        self.assertIn("cannot start", str(cm.exception))

    def test_bridge_that_dies(self):
        c = self.client(FAKE, env={"MUNIX_FAKE_MODE": "die"}, read_timeout=20)
        with self.assertRaises(mx.BridgeError) as cm:
            c.start("p")
        self.assertIn("exited", str(cm.exception))

    def test_bridge_that_hangs(self):
        c = self.client(FAKE, env={"MUNIX_FAKE_MODE": "hang"}, read_timeout=0.5)
        with self.assertRaises(mx.BridgeError) as cm:
            c.start("p")
        self.assertIn("nothing for", str(cm.exception))
        self.assertIsNotNone(c._proc.poll())  # killed

    def test_garbage_from_the_bridge(self):
        c = self.client([sys.executable, "-c", "print('hello'); import time; time.sleep(5)", "--"], read_timeout=20)
        with self.assertRaises(mx.BridgeError) as cm:
            c.start("p")
        self.assertIn("not JSON", str(cm.exception))

    def test_start_failure_is_recorded(self):
        s = mx.MunixSession(ledger_dir=self.tmp.name, binary=FAKE, env={"MUNIX_FAKE_MODE": "die"}, read_timeout=20)
        with self.assertRaises(mx.BridgeError):
            s.start_task("p")
        (summary,) = mx.SUMMARIES
        self.assertIn("exited", summary["error"])


if __name__ == "__main__":
    unittest.main()
