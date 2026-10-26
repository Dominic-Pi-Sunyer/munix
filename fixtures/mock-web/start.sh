#!/usr/bin/env bash
# Start the mock PixelMart site on 127.0.0.1:8080.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec python3 -I server.py
