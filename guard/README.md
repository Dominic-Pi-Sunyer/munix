# guard: Prompt Guard 2 sidecar

A loopback HTTP service that serves Meta's Llama Prompt Guard 2 (22M) as an injection classifier. Munix uses it as a
detector that can only lower trust (invariant 7): the Gate scores free-text fields, and a high score drops that
field's trust. Security does not depend on it.

## Setup

1. Accept the license at https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M and put `HF_TOKEN=...` in the repo
   root `.env` (or export it).
2. `cd guard && uv sync && uv run python download.py`

## Run

    uv run python server.py --port 8091            # real model, offline (local_files_only)
    python3 server.py --port 8091 --fake           # marker-phrase stub, no torch, tests only

Binds `127.0.0.1` only; requests whose `Host` is not `127.0.0.1:<port>` or `localhost:<port>` get 403.

## Test (no torch needed)

    python3 -m unittest discover -s guard/tests -t guard    # from the repo root

## Wire format

`POST /score` with `{"texts": ["...", ...]}` (at most 256 strings, body at most 2 MB) returns
`{"scores": [0.0..1.0, ...]}`, one injection probability per text, in order. Texts over 512 tokens are scored in
overlapping 510-token windows (64 overlap) and take the max. Empty text scores 0.0. Any bad request returns 400 (413
if too large, 403 for a bad Host) with `{}`; input is never echoed or logged.

`GET /health` returns `{"ok": true, "model": "<id or fake>"}`.
