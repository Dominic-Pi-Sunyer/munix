"""Download Llama Prompt Guard 2 (22M) into the Hugging Face cache. Needs an HF token with the license accepted."""

import os
import sys
from pathlib import Path

MODEL = "meta-llama/Llama-Prompt-Guard-2-22M"


def token_from_env_file(path):
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if line.startswith("HF_TOKEN="):
            return line.split("=", 1)[1].strip().strip("'\"") or None
    return None


def main():
    token = os.environ.get("HF_TOKEN") or token_from_env_file(Path(__file__).resolve().parent.parent / ".env")
    if not token:
        sys.exit(
            f"No HF_TOKEN. Accept the license at https://huggingface.co/{MODEL} "
            "and add HF_TOKEN=... to the repo root .env (or export it)."
        )
    from huggingface_hub import snapshot_download

    path = snapshot_download(repo_id=MODEL, token=token)
    print(f"downloaded {MODEL} to {path}")


if __name__ == "__main__":
    main()
