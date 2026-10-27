"""Offline tests for the shared Meta credit floor (scripts/credit.py)."""

import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import credit  # noqa: E402


class CreditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / ".credit.json"

    def test_without_state_a_paid_run_may_not_start(self):
        with self.assertRaises(credit.CreditError):
            credit.check(self.path)
        self.assertEqual(credit.Meter(lambda: 0.0, self.path).stop_reason(), "credit_floor")

    def test_charges_add_up_and_the_floor_stops(self):
        credit.set_balance(26.0, 25.0, self.path)
        self.assertAlmostEqual(credit.check(self.path), 26.0)
        self.assertAlmostEqual(credit.charge(0.6, self.path), 25.4)
        credit.check(self.path)  # still above
        credit.charge(0.4, self.path)
        with self.assertRaises(credit.CreditError):
            credit.check(self.path)  # exactly at the floor stops

    def test_meter_charges_only_the_new_spend_and_stops_at_the_floor(self):
        credit.set_balance(26.0, 25.0, self.path)
        spend = [0.0]
        meter = credit.Meter(lambda: spend[0], self.path)
        self.assertIsNone(meter.stop_reason())
        spend[0] = 0.5
        self.assertIsNone(meter.stop_reason())
        self.assertIsNone(meter.stop_reason())  # settling twice charges once
        self.assertAlmostEqual(credit.remaining(credit._read(self.path)), 25.5)
        spend[0] = 1.2
        self.assertEqual(meter.stop_reason(), "credit_floor")

    def test_parallel_runs_share_the_balance(self):
        credit.set_balance(100.0, 25.0, self.path)

        def spend():
            for _ in range(50):
                credit.charge(0.1, self.path)

        threads = [threading.Thread(target=spend) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertAlmostEqual(credit.remaining(credit._read(self.path)), 80.0, places=4)

    def test_a_broken_file_fails_closed(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(credit.CreditError):
            credit.check(self.path)

    def test_run_py_refuses_a_paid_run_without_credit_state(self):
        env = {**os.environ, "MUNIX_CREDIT_FILE": str(self.path)}
        done = subprocess.run(
            [sys.executable, "-I", str(HERE.parent / "run.py"), "run", "--suite", "banking", "--phase", "utility",
             "--budget", "1"],
            capture_output=True, text=True, timeout=60, env=env,
        )
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("no credit state", done.stderr)

    def test_run_py_refuses_at_the_floor(self):
        credit.set_balance(25.0, 25.0, self.path)
        env = {**os.environ, "MUNIX_CREDIT_FILE": str(self.path)}
        done = subprocess.run(
            [sys.executable, "-I", str(HERE.parent / "run.py"), "run", "--suite", "banking", "--phase", "utility",
             "--budget", "1"],
            capture_output=True, text=True, timeout=60, env=env,
        )
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("floor", done.stderr)


if __name__ == "__main__":
    unittest.main()
