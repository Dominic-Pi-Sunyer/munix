import contextlib
import io
import os
from pathlib import Path
import sys
import unittest

AGENT_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = AGENT_DIR.parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import probe  # noqa: E402
import redteam_bare  # noqa: E402


def make_clean_helpers(**overrides) -> probe.ProbeHelpers:
    def blocked_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
        return (host, port) == ("munix-t-1-relay", 4040)

    def blocked_resolve(host: str, port: int) -> list:
        raise OSError("Name or service not known")

    def scoped_http(method: str, url: str, body=None, headers=None, timeout: float = 2.0) -> int | None:
        if method == "GET" and url.endswith("/models"):
            return 404
        if method == "POST" and url.endswith("/chat/completions"):
            return 403
        return 404

    defaults = dict(
        environ={
            "OPENAI_BASE_URL": "http://munix-t-1-relay:4040/v1",
            "OPENAI_API_KEY": "munix-gateway",
            "MUNIX_WORKER_MODEL": "muse-spark-1.3",
        },
        tcp_connect=blocked_tcp,
        resolve=blocked_resolve,
        http_request=scoped_http,
        iter_scan_files=lambda: [("/agent/agent.py", 120), ("/munix/shim.py", 80)],
        read_bytes=lambda path, max_bytes=probe.MAX_FILE_BYTES: (
            b"python\x00/munix/shim.py\x00serve" if path.startswith("/proc/") else b"print('ok')\n"
        ),
        try_write=lambda d: d == "/tmp",
        path_exists=lambda p: False,
        list_dir=lambda p: ["1", "7", "self", "cpuinfo"] if p == "/proc" else [],
    )
    defaults.update(overrides)
    return probe.ProbeHelpers(**defaults)


class TestProbeChecks(unittest.TestCase):
    def test_internet_tcp_pass_and_fail(self):
        status, _ = probe.check_internet_tcp(make_clean_helpers())
        self.assertEqual(status, "PASS")

        status, detail = probe.check_internet_tcp(
            make_clean_helpers(tcp_connect=lambda host, port, timeout=2.0: (host, port) == ("1.1.1.1", 443))
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("1.1.1.1:443", detail)

    def test_dns_pass_and_fail(self):
        status, _ = probe.check_dns(make_clean_helpers())
        self.assertEqual(status, "PASS")

        status, detail = probe.check_dns(
            make_clean_helpers(resolve=lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 443))])
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("example.com", detail)

    def test_host_services_pass_and_fail(self):
        tried: list[tuple[str, int]] = []

        def record_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
            tried.append((host, port))
            return False

        h = make_clean_helpers(
            environ={"MUNIX_PROBE_HOST": "10.0.2.2", "OPENAI_API_KEY": "munix-gateway"},
            tcp_connect=record_tcp,
        )
        status, _ = probe.check_host_services(h)
        self.assertEqual(status, "PASS")
        for host in ("10.0.2.2", "host.docker.internal"):
            for port in (1025, 8025, 8080):
                self.assertIn((host, port), tried)

        status, detail = probe.check_host_services(
            make_clean_helpers(
                tcp_connect=lambda host, port, timeout=2.0: (host, port) == ("host.docker.internal", 8025)
            )
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("host.docker.internal:8025", detail)

    def test_relay_scope_pass_and_fail(self):
        status, detail = probe.check_relay_scope(make_clean_helpers())
        self.assertEqual(status, "PASS")
        self.assertIn("INFO", detail)

        # Fail if GET /models returns 200
        status, detail = probe.check_relay_scope(
            make_clean_helpers(http_request=lambda m, u, b=None, hdr=None, t=2.0: 200 if m == "GET" else 403)
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("/models", detail)

        # Fail if unallowed model returns 200
        status, detail = probe.check_relay_scope(
            make_clean_helpers(http_request=lambda m, u, b=None, hdr=None, t=2.0: 404 if m == "GET" else 200)
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("unallowed model", detail)

        # Fail if extra relay port is open
        status, detail = probe.check_relay_scope(
            make_clean_helpers(tcp_connect=lambda host, port, timeout=2.0: port in (4040, 22))
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("22", detail)

    def test_keys_in_env_pass_fail_and_never_prints_secret_values(self):
        status, _ = probe.check_keys_in_env(make_clean_helpers())
        self.assertEqual(status, "PASS")

        # The python base image's GPG_KEY (a public fingerprint) is expected, not a leak.
        status, _ = probe.check_keys_in_env(
            make_clean_helpers(environ={"OPENAI_API_KEY": "munix-gateway", "GPG_KEY": "ABCDEF0123"})
        )
        self.assertEqual(status, "PASS")

        fake_openai_secret = "super-secret-openai-value-999"
        fake_other_secret = "ultra-secret-github-token-888"
        h = make_clean_helpers(
            environ={
                "OPENAI_API_KEY": fake_openai_secret,
                "GITHUB_TOKEN": fake_other_secret,
                "AWS_SECRET_ACCESS_KEY": fake_other_secret,
            }
        )
        status, detail = probe.check_keys_in_env(h)
        self.assertEqual(status, "FAIL")
        self.assertIn("OPENAI_API_KEY", detail)
        self.assertIn("GITHUB_TOKEN", detail)
        self.assertIn("AWS_SECRET_ACCESS_KEY", detail)
        self.assertNotIn(fake_openai_secret, detail)
        self.assertNotIn(fake_other_secret, detail)

    def test_keys_in_files_pass_and_fail_paths_only(self):
        status, _ = probe.check_keys_in_files(make_clean_helpers())
        self.assertEqual(status, "PASS")

        # .env file triggers FAIL
        h_dotenv = make_clean_helpers(iter_scan_files=lambda: [("/agent/.env", 10)])
        status, detail = probe.check_keys_in_files(h_dotenv)
        self.assertEqual(status, "FAIL")
        self.assertIn("/agent/.env", detail)

        # The model key assignment pattern in file content triggers FAIL without printing value
        secret_val = b"top_secret_val_12345"
        marker_line = b"".join([b"MODEL_API_", b"KEY="]) + secret_val
        h_marker = make_clean_helpers(
            iter_scan_files=lambda: [("/tmp/leaked.txt", len(marker_line))],
            read_bytes=lambda path, max_bytes=probe.MAX_FILE_BYTES: marker_line,
        )
        status, detail = probe.check_keys_in_files(h_marker)
        self.assertEqual(status, "FAIL")
        self.assertIn("/tmp/leaked.txt", detail)
        self.assertNotIn(secret_val.decode(), detail)

        # sk- followed by 20+ word chars triggers FAIL without printing the key
        sk_secret = b"".join([b"sk-", b"A1b2C3d4E5f6G7h8I9j0K1"])
        h_sk = make_clean_helpers(
            iter_scan_files=lambda: [("/agent/key.txt", len(sk_secret))],
            read_bytes=lambda path, max_bytes=probe.MAX_FILE_BYTES: sk_secret,
        )
        status, detail = probe.check_keys_in_files(h_sk)
        self.assertEqual(status, "FAIL")
        self.assertIn("/agent/key.txt", detail)
        self.assertNotIn(sk_secret.decode(), detail)

        # Files in /proc and /sys or over 1 MiB are skipped
        h_skip = make_clean_helpers(
            iter_scan_files=lambda: [
                ("/proc/1/environ", 100),
                ("/sys/kernel/notes", 100),
                ("/tmp/huge.bin", probe.MAX_FILE_BYTES + 1),
            ],
            read_bytes=lambda path, max_bytes=probe.MAX_FILE_BYTES: sk_secret,
        )
        status, _ = probe.check_keys_in_files(h_skip)
        self.assertEqual(status, "PASS")

    def test_agent_tree_itself_passes_key_scan(self):
        files = []
        for dirpath, _, filenames in os.walk(AGENT_DIR):
            if ".venv" in Path(dirpath).parts or "__pycache__" in Path(dirpath).parts:
                continue
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                files.append((full, os.path.getsize(full)))
        h = make_clean_helpers(iter_scan_files=lambda: files, read_bytes=probe.default_read_bytes)
        status, detail = probe.check_keys_in_files(h)
        self.assertEqual(status, "PASS", detail)

    def test_writable_pass_and_fail(self):
        status, detail = probe.check_writable(make_clean_helpers())
        self.assertEqual(status, "PASS")
        self.assertIn("/tmp writable (INFO)", detail)

        status, detail = probe.check_writable(
            make_clean_helpers(try_write=lambda d: d in ("/tmp", "/agent"))
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("/agent", detail)

    def test_docker_socket_pass_and_fail(self):
        status, _ = probe.check_docker_socket(make_clean_helpers())
        self.assertEqual(status, "PASS")

        status, detail = probe.check_docker_socket(
            make_clean_helpers(path_exists=lambda p: p == "/var/run/docker.sock")
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("/var/run/docker.sock", detail)

    def test_processes_pass_and_fail(self):
        status, detail = probe.check_processes(make_clean_helpers())
        self.assertEqual(status, "PASS")
        self.assertIn("2 numeric pid(s) in /proc (INFO)", detail)

        status, detail = probe.check_processes(
            make_clean_helpers(
                list_dir=lambda p: ["1", "42"],
                read_bytes=lambda path, max_bytes=65536: (
                    b"cargo\x00run\x00-p\x00munix-cli\x00--\x00run" if "42" in path else b"python"
                ),
            )
        )
        self.assertEqual(status, "FAIL")
        self.assertIn("42", detail)

    def test_run_probe_writes_nothing_to_stdout_and_never_leaks_secrets(self):
        fake_openai_key = "NEVER_PRINT_OPENAI_SECRET_VALUE"
        fake_other_key = "NEVER_PRINT_OTHER_KEY_VALUE"
        h = make_clean_helpers(
            environ={
                "OPENAI_BASE_URL": "http://munix-t-1-relay:4040/v1",
                "OPENAI_API_KEY": fake_openai_key,
                "MY_CUSTOM_KEY": fake_other_key,
            }
        )
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            code = probe.run_probe(h)

        self.assertEqual(code, 0)
        self.assertEqual(stdout_buf.getvalue(), "")
        err_text = stderr_buf.getvalue()
        self.assertNotIn(fake_openai_key, err_text)
        self.assertNotIn(fake_other_key, err_text)
        self.assertIn("PROBE FAIL keys_in_env:", err_text)
        self.assertIn("PROBE SUMMARY: 8 pass, 1 fail", err_text)


class TestRedteamRunnerRightSide(unittest.TestCase):
    def test_parse_munix_extracts_summary_and_redacts_secret(self):
        stderr = (
            "munix: sealed 95 files (digest 0123456789ab)\n"
            "munix: task T-01234567, ledger runs/T-01234567.ledger.jsonl, starting the sandbox\n"
            "munix: recovering (attempt 1): withheld 1 item(s)\n"
            "munix: finished\n"
            "munix: context trust 75\n"
            "munix: withheld: step 1 reviews[1] (ugc_review, trust 15): contained the destination of a blocked request\n"
            "munix: ledger runs/T-01234567.ledger.jsonl: 27 entries, chain verified\n"
            "munix: model: 4 calls, 1200 prompt and 300 completion tokens (100 reasoning), about $0.0142\n"
        )
        parsed = redteam_bare.parse_munix(stderr, secret="secret-api-key")
        self.assertEqual(
            parsed,
            {
                "result": "finished",
                "recoveries": 1,
                "context_trust": 75,
                "ledger_entries": 27,
                "ledger_verified": True,
                "withheld": [
                    "step 1 reviews[1] (ugc_review, trust 15): contained the destination of a blocked request"
                ],
                "cost": 0.0142,
            },
        )

    def test_parse_munix_handles_stopped_failed_ledger_and_redaction(self):
        stderr = (
            "munix: stopped: blocked takeover MySecretKey123\n"
            "munix: context trust unknown\n"
            "munix: ledger runs/T-1.ledger.jsonl: check failed: bad hash\n"
        )
        parsed = redteam_bare.parse_munix(stderr, secret="MySecretKey123")
        self.assertEqual(parsed["result"], "stopped: blocked takeover [redacted]")
        self.assertIsNone(parsed["context_trust"])
        self.assertIsNone(parsed["ledger_entries"])
        self.assertFalse(parsed["ledger_verified"])
        self.assertNotIn("MySecretKey123", str(parsed))

    def test_default_out_and_agent_label(self):
        self.assertEqual(
            redteam_bare.default_out_path("left", False, None),
            "docs/redteam/bare-agent.json",
        )
        self.assertEqual(
            redteam_bare.default_out_path("left", True, None),
            "docs/redteam/left-takeover.json",
        )
        self.assertEqual(
            redteam_bare.default_out_path("right", True, "examples/demo-plan-readers.yaml"),
            "docs/redteam/right-takeover-demo-plan-readers.json",
        )
        self.assertEqual(
            redteam_bare.agent_label("left", False, None),
            "bare (demo/left.sh, no Munix)",
        )
        label = redteam_bare.agent_label("right", True, "examples/demo-plan.yaml")
        self.assertIn("right", label)
        self.assertIn("takeover", label)
        self.assertIn("examples/demo-plan.yaml", label)


if __name__ == "__main__":
    unittest.main()
