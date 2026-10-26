import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).parent
AGENT = HERE.parent / "agent.py"
FAKE_SERVER = f"{sys.executable} {HERE / 'fake_mcp_server.py'}"


def tool_call(call_id, name, arguments):
    """A scripted assistant reply that calls one tool. `arguments` may be a dict or a raw string."""
    raw = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": raw}}],
    }


def text_reply(text):
    return {"role": "assistant", "content": text}


class FakeOpenAI:
    """OpenAI-compatible server on a thread. Replies are scripted; the last one repeats."""

    def __init__(self):
        self.replies = []
        self.usages = []  # optional per-reply usage objects; missing entries default to 1 prompt / 1 completion
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                index = min(len(outer.requests) - 1, len(outer.replies) - 1)
                message = outer.replies[index]
                finish = "tool_calls" if message.get("tool_calls") else "stop"
                payload = {
                    "id": "chatcmpl-fake",
                    "object": "chat.completion",
                    "created": 0,
                    "model": body.get("model", "fake"),
                    "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                    "usage": (
                        outer.usages[index]
                        if index < len(outer.usages)
                        else {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                    ),
                }
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake_openai():
    server = FakeOpenAI()
    yield server
    server.close()


@pytest.fixture
def run_agent(fake_openai):
    def run(*extra, prompt="do the task", env=None, server=FAKE_SERVER):
        environment = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI_", "MUNIX_"))}
        environment.update({"OPENAI_BASE_URL": fake_openai.url, "OPENAI_API_KEY": "sk-test-not-real"})
        environment.update(env or {})
        environment = {k: v for k, v in environment.items() if v is not None}
        return subprocess.run(
            [sys.executable, str(AGENT), "--server", server, *extra, prompt],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )

    return run
