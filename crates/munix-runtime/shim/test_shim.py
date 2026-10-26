"""Tests for munix_shim.py. Run from the repo root:

    python3 -m unittest crates/munix-runtime/shim/test_shim.py
"""

import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

SHIM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "munix_shim.py")
TIMEOUT = 20

# An agent that, like a real one, starts `connect` as its MCP server subprocess, sends one line, reads one reply
# and prints it. Its prints must land on the shim's stderr, never on the channel.
ROUNDTRIP_AGENT = r"""
import os, subprocess, sys
p = subprocess.Popen([sys.executable, os.environ["SHIM"], "connect"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p.stdin.write(b'{"from":"agent"}\n')
p.stdin.flush()
reply = p.stdout.readline().decode().strip()
print("AGENT-PRINT", flush=True)
print("REPLY=" + reply, flush=True)
p.stdin.close()
p.wait()
sys.exit(int(os.environ.get("AGENT_EXIT", "0")))
"""


class Harness:
    def __init__(self, test, agent_code, extra_env=None, pre_socket=None):
        self.dir = tempfile.mkdtemp(prefix="munix-shim-", dir="/tmp")
        test.addCleanup(shutil.rmtree, self.dir, True)
        self.sock = os.path.join(self.dir, "mcp.sock")
        env = dict(os.environ, MUNIX_SHIM_SOCKET=self.sock, SHIM=SHIM)
        env.update(extra_env or {})
        if pre_socket:
            pre_socket(self.sock)
        self.proc = subprocess.Popen(
            [sys.executable, SHIM, "serve", "--", sys.executable, "-c", agent_code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        test.addCleanup(self.cleanup)

    def cleanup(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                pipe.close()
            except OSError:
                pass

    def finish(self):
        """Waits for the shim to exit; returns (exit code, remaining stdout, stderr)."""
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        code = self.proc.wait(TIMEOUT)
        return code, self.proc.stdout.read(), self.proc.stderr.read()


class ServeTests(unittest.TestCase):
    def test_a_line_each_way_and_the_agents_prints_stay_off_the_channel(self):
        h = Harness(self, ROUNDTRIP_AGENT)
        self.assertEqual(h.proc.stdout.readline(), b'{"from":"agent"}\n')
        h.proc.stdin.write(b'{"to":"agent"}\n')
        h.proc.stdin.flush()
        code, rest, err = h.finish()
        self.assertEqual(code, 0)
        self.assertEqual(rest, b"")  # nothing else, in particular not the agent's prints
        self.assertIn(b"AGENT-PRINT", err)
        self.assertIn(b'REPLY={"to":"agent"}', err)

    def test_the_agents_exit_code_is_the_shims(self):
        h = Harness(self, ROUNDTRIP_AGENT, {"AGENT_EXIT": "7"})
        h.proc.stdout.readline()
        h.proc.stdin.write(b"{}\n")
        h.proc.stdin.flush()
        code, _, _ = h.finish()
        self.assertEqual(code, 7)

    def test_an_agent_that_exits_before_connecting_gives_its_code(self):
        h = Harness(self, "import sys; print('bye'); sys.exit(3)")
        code, out, err = h.finish()
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertIn(b"bye", err)

    def test_the_agent_gets_no_stdin(self):
        h = Harness(self, "import sys; sys.exit(0 if sys.stdin.read() == '' else 9)")
        code, out, _ = h.finish()
        self.assertEqual(code, 0)
        self.assertEqual(out, b"")

    def test_the_socket_is_private_and_a_stale_one_is_replaced(self):
        def stale(path):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(path)
            s.close()

        agent = (
            "import os, stat, sys\n"
            "p = os.environ['MUNIX_SHIM_SOCKET']\n"
            "print('MODE %o' % stat.S_IMODE(os.stat(p).st_mode), flush=True)\n"
            "sys.exit(0)\n"
        )
        h = Harness(self, agent, pre_socket=stale)
        code, _, err = h.finish()
        self.assertEqual(code, 0)
        self.assertIn(b"MODE 600", err)
        self.assertFalse(os.path.exists(h.sock))

    def test_a_second_connection_is_refused(self):
        agent = r"""
import os, socket, sys
path = os.environ["MUNIX_SHIM_SOCKET"]
first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
first.connect(path)
first.sendall(b"first\n")
print("FIRST-SENT", flush=True)
assert first.makefile("rb").readline() == b"ack\n"
second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
second.settimeout(3)
try:
    second.connect(path)
except OSError:
    print("SECOND refused", flush=True)
else:
    try:
        data = second.recv(10)
        print("SECOND closed" if data == b"" else "SECOND accepted", flush=True)
    except ConnectionError:
        print("SECOND closed", flush=True)
    except OSError:
        print("SECOND accepted", flush=True)
"""
        h = Harness(self, agent)
        self.assertEqual(h.proc.stdout.readline(), b"first\n")
        h.proc.stdin.write(b"ack\n")
        h.proc.stdin.flush()
        code, _, err = h.finish()
        self.assertEqual(code, 0, err)
        self.assertTrue(b"SECOND refused" in err or b"SECOND closed" in err, err)

    def test_sigterm_is_forwarded_to_the_agent(self):
        h = Harness(self, "import time; print('up', flush=True); time.sleep(60)")
        time.sleep(0.5)
        h.proc.send_signal(signal.SIGTERM)
        code, _, _ = h.finish()
        self.assertEqual(code, 128 + signal.SIGTERM)

    def test_the_host_closing_its_side_lets_the_agent_finish(self):
        agent = r"""
import os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(os.environ["MUNIX_SHIM_SOCKET"])
data = s.makefile("rb").read()
print("EOF after %d bytes" % len(data), flush=True)
"""
        h = Harness(self, agent)
        h.proc.stdin.write(b"hello\n")
        h.proc.stdin.flush()
        code, _, err = h.finish()
        self.assertEqual(code, 0)
        self.assertIn(b"EOF after 6 bytes", err)

    def test_usage_errors(self):
        for argv in ([], ["serve"], ["serve", "--"], ["serve", "x"], ["connect", "x"], ["nope"]):
            r = subprocess.run([sys.executable, SHIM, *argv], capture_output=True, timeout=TIMEOUT)
            self.assertEqual(r.returncode, 2, argv)
            self.assertEqual(r.stdout, b"")

    def test_a_missing_agent_command_is_a_clean_failure(self):
        d = tempfile.mkdtemp(prefix="munix-shim-", dir="/tmp")
        self.addCleanup(shutil.rmtree, d, True)
        r = subprocess.run(
            [sys.executable, SHIM, "serve", "--", "/no/such/program"],
            capture_output=True,
            timeout=TIMEOUT,
            env=dict(os.environ, MUNIX_SHIM_SOCKET=os.path.join(d, "s")),
        )
        self.assertEqual(r.returncode, 127)


class ConnectTests(unittest.TestCase):
    def test_connect_retries_until_the_socket_appears_and_pumps_both_ways(self):
        d = tempfile.mkdtemp(prefix="munix-shim-", dir="/tmp")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "s")
        env = dict(os.environ, MUNIX_SHIM_SOCKET=path)
        p = subprocess.Popen(
            [sys.executable, SHIM, "connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
        )
        self.addCleanup(p.kill)
        received = []

        def server():
            time.sleep(0.5)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(path)
            srv.listen(1)
            conn, _ = srv.accept()
            received.append(conn.makefile("rb").readline())
            conn.sendall(b"pong\n")
            conn.close()
            srv.close()

        t = threading.Thread(target=server)
        t.start()
        p.stdin.write(b"ping\n")
        p.stdin.flush()
        self.assertEqual(p.stdout.readline(), b"pong\n")
        self.assertEqual(p.wait(TIMEOUT), 0)
        t.join(TIMEOUT)
        self.assertEqual(received, [b"ping\n"])
        p.stdin.close()
        p.stdout.close()


if __name__ == "__main__":
    unittest.main()
