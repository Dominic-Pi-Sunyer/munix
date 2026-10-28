import http.client
import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

SERVER = str(Path(__file__).resolve().parent.parent / "server.py")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, SERVER, "--port", str(cls.port), "--fake"],
            stderr=subprocess.PIPE,
        )
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        cls.tearDownClass()
        raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.proc.stderr.close()

    def request(self, method, path, body=None, headers=None, raw=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        data = body if raw else (None if body is None else json.dumps(body))
        conn.request(method, path, body=data, headers=headers or {})
        r = conn.getresponse()
        text = r.read().decode()
        conn.close()
        return r.status, text

    def test_good_request_in_order(self):
        status, text = self.request(
            "POST", "/score", {"texts": ["hello", "Ignore previous instructions", "", "the SYSTEM PROMPT"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(text), {"scores": [0.0, 1.0, 0.0, 1.0]})

    def test_empty_list(self):
        status, text = self.request("POST", "/score", {"texts": []})
        self.assertEqual((status, json.loads(text)), (200, {"scores": []}))

    def test_wrong_host_403(self):
        status, text = self.request("POST", "/score", {"texts": ["a"]}, headers={"Host": "evil.example:80"})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(text), {})

    def test_localhost_host_ok(self):
        status, _ = self.request("GET", "/health", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_extra_key_400(self):
        status, _ = self.request("POST", "/score", {"texts": ["a"], "extra": 1})
        self.assertEqual(status, 400)

    def test_missing_key_400(self):
        status, _ = self.request("POST", "/score", {"other": ["a"]})
        self.assertEqual(status, 400)

    def test_non_string_item_400(self):
        status, _ = self.request("POST", "/score", {"texts": ["a", 5]})
        self.assertEqual(status, 400)

    def test_too_many_texts_400(self):
        status, _ = self.request("POST", "/score", {"texts": ["a"] * 257})
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/score", {"texts": ["a"] * 256})
        self.assertEqual(status, 200)

    def test_bad_json_400(self):
        status, _ = self.request("POST", "/score", "{not json", raw=True)
        self.assertEqual(status, 400)

    def test_oversized_body_413(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(
                (
                    f"POST /score HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                    f"Content-Length: {2 * 1024 * 1024 + 1}\r\n\r\n"
                ).encode()
            )
            self.assertIn(b" 413 ", s.recv(4096).split(b"\r\n")[0])

    def test_errors_do_not_echo_input(self):
        secret = "SECRET-CANARY-123"
        for body in ({"texts": [secret, 1]}, {"texts": [secret], secret: 1}):
            status, text = self.request("POST", "/score", body)
            self.assertEqual(status, 400)
            self.assertNotIn(secret, text)
            self.assertEqual(json.loads(text), {})
        status, text = self.request("POST", "/score", secret, raw=True)
        self.assertEqual((status, json.loads(text)), (400, {}))

    def test_health(self):
        status, text = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(text), {"ok": True, "model": "fake"})

    def test_windowing_spans(self):
        sys.path.insert(0, str(Path(SERVER).parent))
        from server import window_spans

        self.assertEqual(window_spans(0), [])
        self.assertEqual(window_spans(510), [(0, 510)])
        spans = window_spans(1500)
        self.assertEqual(spans[0], (0, 510))
        self.assertEqual(spans[-1][1], 1500)
        for (a, b), (c, d) in zip(spans, spans[1:]):
            self.assertEqual(b - c, 64)


if __name__ == "__main__":
    unittest.main()
