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
TYPES = {"text", "iban", "number", "int", "bool", "date", "enum"}
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
                fields = convert.to_fields(name, result, env)
                self.assertEqual(set(fields), convert.raw_fields(name))
                self.assertEqual(fields, convert.to_fields("banking." + name, result, env))
                json.dumps(fields)  # plain JSON values only
                # Every per-row array has one element per transaction.
                lists = [v for k, v in fields.items() if isinstance(v, list)]
                self.assertEqual(len({len(v) for v in lists}), 1 if lists else 0)

    def test_recent_transactions_are_labeled_by_who_wrote_each_value(self):
        env, rt = new_env(), runtime()
        me = env.bank_account.iban
        result, _ = rt.run_function(env, "get_most_recent_transactions", {})
        self.assertGreater(len(result), 0)
        fields = convert.to_fields("get_most_recent_transactions", result, env)
        self.assertEqual(
            set(fields),
            {"ids", "paid_to", "paid_by", "sent_by_me", "amounts", "my_subjects", "their_subjects", "dates", "recurring"},
        )
        for key, values in fields.items():
            self.assertEqual(len(values), len(result), key)  # parallel arrays
        for field in ("paid_to", "paid_by"):
            for iban in fields[field]:
                self.assertNotEqual(iban, "me")
                self.assertRegex(iban, IBAN)
        for date in fields["dates"]:
            self.assertRegex(date, DATE)
        self.assertTrue(all(isinstance(a, float) for a in fields["amounts"]))
        # transaction 1 was sent by the user: the user chose the recipient and wrote the subject
        i = fields["ids"].index(1)
        self.assertTrue(fields["sent_by_me"][i])
        self.assertEqual(fields["paid_to"][i], "CH9300762011623852957")
        self.assertEqual(fields["paid_by"][i], me)
        self.assertEqual(fields["my_subjects"][i], "Pizza party")
        self.assertEqual(fields["their_subjects"][i], "")
        # transaction 5 is the incoming payment: the sender is paid_by, the user's own IBAN is paid_to, and the
        # subject is the sender's
        i = fields["ids"].index(5)
        self.assertFalse(fields["sent_by_me"][i])
        self.assertEqual(fields["paid_by"][i], "GB29NWBK60161331926819")
        self.assertEqual(fields["paid_to"][i], me)
        self.assertEqual(fields["my_subjects"][i], "")
        self.assertEqual(fields["their_subjects"][i], "Sushi dinner")
        # every subject is in exactly one of the two arrays
        for mine, my, their, subject in zip(
            fields["sent_by_me"], fields["my_subjects"], fields["their_subjects"], [t.subject for t in result]
        ):
            self.assertEqual((my, their), (subject, "") if mine else ("", subject))

    def test_recent_transactions_need_the_environment_for_the_users_iban(self):
        env, rt = new_env(), runtime()
        result, _ = rt.run_function(env, "get_most_recent_transactions", {})
        with self.assertRaises(ValueError):
            convert.to_fields("get_most_recent_transactions", result)

    def test_scheduled_transactions_are_the_users_own_records(self):
        env, rt = new_env(), runtime()
        result, _ = rt.run_function(env, "get_scheduled_transactions", {})
        fields = convert.to_fields("get_scheduled_transactions", result)  # needs no env
        self.assertEqual(
            set(fields), {"ids", "counterparties", "sent_by_me", "amounts", "subjects", "dates", "recurring"}
        )
        self.assertEqual(fields["ids"], [t.id for t in result])
        self.assertEqual(fields["counterparties"], [t.recipient for t in result])
        for iban in fields["counterparties"]:
            self.assertRegex(iban, IBAN)

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
        # Files and strangers' subjects reach the agent only through Readers: small typed values, labeled with the
        # raw text's region.
        self.assertEqual(
            {spec["region"] for spec in convert.MANIFESTS["read_file"]["output"].values()}, {"unclassified"}
        )
        for tool, (raw, region, typed) in convert.READER_FIELDS.items():
            out = convert.MANIFESTS[tool]["output"]
            self.assertNotIn(raw, out)
            self.assertTrue(typed <= set(out), tool)
            for field in typed:
                self.assertEqual(out[field]["region"], region, field)
                self.assertTrue(out[field]["type"].startswith(("enum", "bool", "int")), field)
        # Labels follow who wrote each value: anyone can send the user money, so the sender and the subject of an
        # incoming payment are third-party; where the user's own money went and what the user wrote are not.
        expected = {
            "paid_to": ("operator_content", "iban[]", "public"),
            "paid_by": ("ugc_comment", "iban[]", "public"),
            "my_subjects": ("user_content", "text[]", "private"),
            "their_subject_kinds": ("ugc_comment", "enum[]", "private"),
            "their_subject_flags": ("ugc_comment", "bool[]", "private"),
        }
        for field, (region, ty, confidential) in expected.items():
            self.assertEqual(
                (recent[field]["region"], recent[field]["type"], recent[field]["confidential"]),
                (region, ty, confidential),
                field,
            )
        for field in ("ids", "sent_by_me", "amounts", "dates", "recurring"):
            self.assertEqual(recent[field]["region"], "operator_content")
        for gone in ("counterparties", "payees", "subjects"):
            self.assertNotIn(gone, recent)
        scheduled = convert.MANIFESTS["get_scheduled_transactions"]["output"]
        self.assertEqual({spec["region"] for spec in scheduled.values()}, {"user_content"})


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
        self.assertEqual(fields["paid_by"], [env.bank_account.iban, "GB29NWBK60161331926819"])
        self.assertEqual(fields["paid_to"], ["US122000000121212121212", env.bank_account.iban])

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


class SimulatedUserFlagTest(unittest.TestCase):
    """The flag reaches the `munix bridge` command line, and only when asked for."""

    def setUp(self):
        mx.SUMMARIES.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.argv_out = Path(self.tmp.name) / "argv.json"
        self.spy = Path(self.tmp.name) / "spy.py"
        self.spy.write_text(
            "import json, os, runpy, sys\n"
            "open(os.environ['ARGV_OUT'], 'w').write(json.dumps(sys.argv[1:]))\n"
            f"runpy.run_path({str(HERE / 'fake_bridge.py')!r}, run_name='__main__')\n",
            encoding="utf-8",
        )
        self.binary = [sys.executable, str(self.spy)]

    def bridge_argv(self, simulated_user):
        client = mx.BridgeClient(
            convert.MANIFEST_DIR, Path(self.tmp.name) / "l.jsonl", self.binary, 20.0,
            env={"ARGV_OUT": str(self.argv_out)}, simulated_user=simulated_user,
        )
        try:
            client.start("hello")
            client.end()
        finally:
            client.kill()
        return json.loads(self.argv_out.read_text())

    def test_client_passes_the_flag_only_when_asked(self):
        self.assertNotIn("--simulated-user", self.bridge_argv(False))
        argv = self.bridge_argv(True)
        self.assertEqual(argv[0], "bridge")
        self.assertIn("--simulated-user", argv)

    def test_session_passes_the_flag_to_every_bridge(self):
        s = mx.MunixSession(
            ledger_dir=self.tmp.name, tag="t", binary=self.binary, read_timeout=20,
            env={"ARGV_OUT": str(self.argv_out)}, simulated_user=True,
        )
        self.addCleanup(s.close)
        s.start_task("a task")
        self.assertIn("--simulated-user", json.loads(self.argv_out.read_text()))

    def test_plan_memory_reaches_every_bridge_and_the_summary_says_where_the_plan_came_from(self):
        memory = Path(self.tmp.name) / "plan-memory"
        s = mx.MunixSession(
            ledger_dir=self.tmp.name, tag="t", binary=self.binary, read_timeout=20,
            env={"ARGV_OUT": str(self.argv_out)}, plan_memory=memory,
        )
        self.addCleanup(s.close)
        s.start_task("a task")
        argv = json.loads(self.argv_out.read_text())
        self.assertEqual(argv[argv.index("--plan-memory") + 1], str(memory))
        s.close()
        self.assertEqual(mx.SUMMARIES[-1]["plan"], "memory:exact")  # the fake bridge's answer when memory is on
        # Without it, no flag and the planner's plan.
        self.assertNotIn("--plan-memory", self.bridge_argv(False))

    def test_run_py_tags_the_setup_and_leaves_existing_names_alone(self):
        import run

        self.assertEqual(run.setup_tag("munix", False, run.DEFAULT_MODEL), "munix")
        self.assertEqual(run.setup_tag("munix", True, run.DEFAULT_MODEL), "munix-takeover")
        self.assertEqual(run.setup_tag("bare", False, run.DEFAULT_MODEL), "bare")
        self.assertEqual(run.setup_tag("munix", False, run.DEFAULT_MODEL, simulated_user=True), "munix-simuser")
        self.assertEqual(run.setup_tag("munix", False, run.DEFAULT_MODEL, plan_memory=True), "munix-memory")
        self.assertEqual(run.setup_tag("munix", True, run.DEFAULT_MODEL, True), "munix-takeover-simuser")
        self.assertEqual(
            run.result_name("munix-simuser", "banking", "utility", None), "munix-simuser--banking-utility.json"
        )


class BudgetTest(unittest.TestCase):
    def test_supervisor_cost_sums_every_bridge_and_skips_missing_usage(self):
        import run

        summaries = [
            {"supervisor_usage": {"calls": 2, "prompt_tokens": 1_000_000, "completion_tokens": 0}},
            {"supervisor_usage": {"calls": 1, "prompt_tokens": 0, "completion_tokens": 1_000_000}},
            {"error": "the bridge died"},  # no usage reported
            {"supervisor_usage": None},
        ]
        self.assertAlmostEqual(run.supervisor_cost(summaries, 1.25, 4.25), 5.50)

    def test_cases_stop_before_the_one_that_would_start_over_budget(self):
        import run

        spend = [0.0]
        ran = []

        def one(case):
            ran.append(case)
            spend[0] += 0.4

        stop = lambda: "budget" if spend[0] >= 1.0 else None  # noqa: E731
        self.assertEqual(run.run_cases([1, 2, 3, 4], one, stop), "budget")
        self.assertEqual(ran, [1, 2, 3])  # 0.0, 0.4, 0.8 are under $1; 1.2 is not

    def test_without_a_stop_every_case_runs(self):
        import run

        ran = []
        self.assertIsNone(run.run_cases([1, 2], ran.append, lambda: None))
        self.assertEqual(ran, [1, 2])

    def test_meta_runs_need_a_budget(self):
        import subprocess

        for extra in ([], ["--budget", "0"]):
            done = subprocess.run(
                [sys.executable, "-I", str(HERE.parent / "run.py"), "run", "--suite", "banking", "--phase", "utility",
                 *extra],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(done.returncode, 2, done.stderr)
            self.assertIn("--budget USD is required", done.stderr)


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
        self.assertEqual(one["supervisor_usage"], {"calls": 1, "prompt_tokens": 1000, "completion_tokens": 100})
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

    def test_a_task_munix_cannot_start_is_refused_not_a_crash(self):
        s = mx.MunixSession(ledger_dir=self.tmp.name, binary=FAKE, env={"MUNIX_FAKE_MODE": "die"}, read_timeout=20)
        self.addCleanup(s.close)
        rt, env = runtime(), new_env()
        before = env.bank_account.balance
        mx.MunixStart(s).query("p", rt, env, [], {})  # does not raise
        self.assertTrue(s.refused)
        _, _, env, msgs, _ = mx.MunixToolsExecutor(s).query(
            "p", rt, env, assistant_with(("send_money", {"recipient": "X", "amount": 1.0, "subject": "s", "date": "2022-01-01"})), {}
        )
        self.assertEqual(msgs[-1]["error"], "denied: task refused")
        self.assertEqual(env.bank_account.balance, before)
        (summary,) = mx.SUMMARIES
        self.assertIn("error", summary)


if __name__ == "__main__":
    unittest.main()
