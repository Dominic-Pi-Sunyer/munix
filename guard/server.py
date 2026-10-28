"""Loopback HTTP sidecar serving Llama Prompt Guard 2 as an injection classifier.

POST /score  {"texts": [..]}  ->  {"scores": [..]}   (injection probability per text, in order)
GET  /health                  ->  {"ok": true, "model": "<id or fake>"}

Binds 127.0.0.1 only. Never logs text.
"""

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_TEXTS = 256
MAX_BODY = 2 * 1024 * 1024
WINDOW = 510  # tokens per window, before special tokens
OVERLAP = 64
BATCH = 32
DEFAULT_MODEL = "meta-llama/Llama-Prompt-Guard-2-22M"
FAKE_MARKERS = ("ignore previous", "ignore all previous", "new instructions", "system prompt")


class FakeScorer:
    name = "fake"

    def score(self, texts):
        return [1.0 if any(m in t.lower() for m in FAKE_MARKERS) else 0.0 for t in texts]


def window_spans(n, window=WINDOW, overlap=OVERLAP):
    """Start/end token offsets of overlapping windows covering n tokens (at least one span for n > 0)."""
    if n <= 0:
        return []
    if n <= window:
        return [(0, n)]
    step = window - overlap
    spans = []
    start = 0
    while True:
        end = min(start + window, n)
        spans.append((start, end))
        if end == n:
            break
        start += step
    return spans


class ModelScorer:
    def __init__(self, model_id):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.name = model_id
        self.tokenizer = AutoTokenizer.from_pretrained(model_id, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_id, local_files_only=True)
        self.model.eval()
        labels = self.model.config.id2label
        if len(labels) != 2:
            raise SystemExit(f"expected exactly 2 labels, model has {len(labels)}")
        # Index 1 is the malicious class. The label names are printed (names only) so a mismatch is visible.
        print(f"labels: {dict(labels)}", file=sys.stderr)
        self.lock = threading.Lock()

    def _windows(self, text):
        ids = self.tokenizer(text, add_special_tokens=False)["input_ids"]
        return [
            self.tokenizer.build_inputs_with_special_tokens(ids[a:b]) for a, b in window_spans(len(ids))
        ]

    def score(self, texts):
        torch = self.torch
        scores = [0.0] * len(texts)
        flat = []  # (text index, input ids)
        for i, t in enumerate(texts):
            if not t:
                continue
            for w in self._windows(t):
                flat.append((i, w))
        pad = self.tokenizer.pad_token_id or 0
        with self.lock, torch.no_grad():
            for s in range(0, len(flat), BATCH):
                chunk = flat[s : s + BATCH]
                width = max(len(w) for _, w in chunk)
                ids = torch.tensor([w + [pad] * (width - len(w)) for _, w in chunk])
                mask = torch.tensor([[1] * len(w) + [0] * (width - len(w)) for _, w in chunk])
                logits = self.model(input_ids=ids, attention_mask=mask).logits
                probs = torch.softmax(logits, dim=-1)[:, 1].tolist()
                for (i, _), p in zip(chunk, probs):
                    scores[i] = max(scores[i], float(p))
        return scores


def make_handler(scorer, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if code >= 400:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self):
            return self.headers.get("Host", "") in allowed_hosts

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {})
            if self.path == "/health":
                return self._send(200, {"ok": True, "model": scorer.name})
            self._send(404, {})

        def do_POST(self):
            t0 = time.monotonic()
            if not self._host_ok():
                return self._send(403, {})
            if self.path != "/score":
                return self._send(404, {})
            length = self.headers.get("Content-Length")
            if length is None or not length.isdigit():
                return self._send(400, {})
            length = int(length)
            if length > MAX_BODY:
                return self._send(413, {})
            try:
                data = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                return self._send(400, {})
            if not isinstance(data, dict) or set(data) != {"texts"}:
                return self._send(400, {})
            texts = data["texts"]
            if (
                not isinstance(texts, list)
                or len(texts) > MAX_TEXTS
                or not all(isinstance(t, str) for t in texts)
            ):
                return self._send(400, {})
            try:
                scores = scorer.score(texts)
            except Exception:
                print("score error", file=sys.stderr)
                return self._send(500, {})
            ms = (time.monotonic() - t0) * 1000
            print(f"score texts={len(texts)} bytes={length} ms={ms:.1f}", file=sys.stderr, flush=True)
            self._send(200, {"scores": scores})

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8091)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--fake", action="store_true")
    args = ap.parse_args()
    if args.fake:
        print("FAKE DETECTOR", file=sys.stderr, flush=True)
        scorer = FakeScorer()
    else:
        scorer = ModelScorer(args.model)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(scorer, args.port))
    print(f"listening on 127.0.0.1:{args.port} model={scorer.name}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
