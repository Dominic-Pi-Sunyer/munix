"""Tiny fake Web Speed MCP server (stdio) returning a canned `interpret_page` result."""

import json
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fake-web-speed")

PAGE = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}


@mcp.tool()
async def interpret_page(url: str, js: bool = False, wait_for: str | None = None) -> dict[str, Any]:
    if "blocked" in url:
        return {"error": True, "code": "BLOCKED", "message": "SECRET-REMOTE-TEXT", "url": url}
    return PAGE


if __name__ == "__main__":
    mcp.run()
