"""A tiny MCP stdio server with two tools, for the agent tests."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fake")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the text back."""
    return f"echo: {text}"


@mcp.tool()
def boom() -> str:
    """Always fails."""
    raise ValueError("it broke")


if __name__ == "__main__":
    mcp.run("stdio")
