"""demo-direct: the undefended baseline MCP server for the Munix demo (left side of the split screen).

Wires `web_open` straight to Web Speed OSS and `email_send` straight to the local SMTP sink. There is
deliberately no prompt-injection defence here: the page text goes to the agent exactly as Web Speed returns it.
The only guard is that mail may never leave the machine (non-loopback SMTP is refused).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shlex
import smtplib
import sys
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

REPO_ROOT = Path(__file__).resolve().parents[2]
SENDER = "agent@demo.local"
DEFAULT_ALLOW_HOSTS = "pixelmart.test:8080"
DEFAULT_SMTP = "127.0.0.1:1025"
WEBSPEED_TIMEOUT_SECS = 60
SMTP_TIMEOUT_SECS = 10

mcp = FastMCP("demo-direct")


def _fail(message: str) -> ToolError:
    """A tool error with a short fixed message. Never carries remote text or a traceback."""
    return ToolError(message)


# --------------------------------------------------------------------------------------------------------
# web_open
# --------------------------------------------------------------------------------------------------------


def _webspeed_params() -> StdioServerParameters:
    override = os.environ.get("WEBSPEED_COMMAND")  # test hook: replaces the real Web Speed launch command
    if override:
        argv = shlex.split(override)
    else:
        oss_dir = Path(os.environ.get("WEBSPEED_OSS_DIR") or "../web-speed-oss")
        if not oss_dir.is_absolute():
            oss_dir = REPO_ROOT / oss_dir
        argv = [str(oss_dir / "venv" / "bin" / "python"), str(oss_dir / "server.py")]
    env = {"WEBSPEED_ALLOW_HOSTS": os.environ.get("WEBSPEED_ALLOW_HOSTS") or DEFAULT_ALLOW_HOSTS}
    return StdioServerParameters(command=argv[0], args=argv[1:], env=env)


async def _interpret_page(url: str) -> dict[str, Any]:
    async with stdio_client(_webspeed_params(), errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("interpret_page", {"url": url, "read": True})
    if result.isError:
        raise ValueError("web speed tool error")
    data: Any = None
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            data = json.loads(text)
            break
    if data is None:
        data = result.structuredContent
    if not isinstance(data, dict):
        raise ValueError("unexpected web speed result")
    return data


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return " ".join(str(value).split())


def _lines_of(value: Any) -> list[str]:
    """Flatten a string, list or dict from Web Speed into text lines."""
    if value is None or value == "":
        return []
    if isinstance(value, dict):
        parts = [f"{k}: {_scalar(v)}" for k, v in value.items() if v not in (None, "") and not isinstance(v, (dict, list))]
        return [" | ".join(parts)] if parts else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_lines_of(item))
        return out
    text = _scalar(value)
    return [text] if text else []


def _text_of(item: Any, keys: tuple[str, ...]) -> str:
    if isinstance(item, dict):
        for key in keys:
            if item.get(key):
                return _scalar(item[key])
        return ""
    return _scalar(item) if item else ""


def render_page(data: dict[str, Any]) -> str:
    """Render a Web Speed `interpret_page` map as the demo's plain-text page."""
    lines: list[str] = [f"Title: {_scalar(data.get('title') or '')}"]

    for heading in data.get("headings") or []:
        text = _text_of(heading, ("text", "title"))
        if text:
            lines.append(text)
    for block in data.get("text_blocks") or []:
        text = _text_of(block, ("text",))
        if text:
            lines.append(text)

    article = data.get("article")
    sections = data.get("sections") or (article.get("sections") if isinstance(article, dict) else None) or []
    for section in sections:
        if isinstance(section, dict):
            for key in ("heading", "title"):
                if section.get(key):
                    lines.append(_scalar(section[key]))
                    break
            for key in ("text", "body", "content"):
                lines.extend(_lines_of(section.get(key)))
        else:
            lines.extend(_lines_of(section))
    if isinstance(article, str):
        lines.extend(_lines_of(article))

    product = data.get("product") or data.get("product_fields")
    if product:
        if isinstance(product, dict):
            lines.extend(f"{k}: {_scalar(v)}" for k, v in product.items() if v not in (None, "") and not isinstance(v, (dict, list)))
        else:
            lines.extend(_lines_of(product))

    items = data.get("listing_items") or data.get("items")
    if items:
        for item in items:
            if isinstance(item, dict):
                parts = [_scalar(v) for v in item.values() if v not in (None, "") and not isinstance(v, (dict, list))]
                if parts:
                    lines.append(" | ".join(parts))
            else:
                lines.extend(_lines_of(item))

    for table in data.get("tables") or []:
        headers = table.get("headers") or []
        if headers:
            lines.append(" | ".join(_scalar(h) for h in headers))
        for row in table.get("rows") or []:
            lines.append(" | ".join(_scalar(cell) for cell in row))

    urls: list[str] = []
    content_links = data.get("content_links") or {}
    link_items = content_links.get("items") if isinstance(content_links, dict) else content_links
    for link in link_items or []:
        url = link.get("url") if isinstance(link, dict) else link
        if url and url not in urls:
            urls.append(str(url))
    for link in data.get("navigation") or []:
        url = link.get("url") if isinstance(link, dict) else link
        if url and url not in urls:
            urls.append(str(url))

    lines.append("Links:")
    lines.extend(urls)
    return "\n".join(lines)


@mcp.tool()
async def web_open(url: str) -> str:
    """Open a web page and return its content as plain text: a Title line, the page text, and a Links section."""
    try:
        data = await asyncio.wait_for(_interpret_page(url), WEBSPEED_TIMEOUT_SECS)
    except Exception:  # noqa: BLE001 - nothing from the remote side may reach the caller
        raise _fail("The page could not be opened.") from None
    if data.get("error"):
        raise _fail("The page could not be opened.")
    try:
        return render_page(data)
    except Exception:  # noqa: BLE001
        raise _fail("The page could not be read.") from None


# --------------------------------------------------------------------------------------------------------
# email_send
# --------------------------------------------------------------------------------------------------------


def _smtp_endpoint() -> tuple[str, int]:
    """Parse MUNIX_SMTP and refuse anything that is not loopback (fail closed)."""
    raw = os.environ.get("MUNIX_SMTP") or DEFAULT_SMTP
    host, sep, port_text = raw.rpartition(":")
    if not sep or not port_text.isdigit():
        raise ValueError("bad smtp endpoint")
    host = host.strip("[]")
    port = int(port_text)
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("non-loopback smtp")
        except ValueError:
            raise ValueError("non-loopback smtp") from None
    if not 0 < port < 65536:
        raise ValueError("bad smtp port")
    return host, port


def _send(to: list[str], subject: str, body: str, cc: list[str]) -> str:
    host, port = _smtp_endpoint()
    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    message_id = make_msgid(domain="demo.local")
    msg["Message-ID"] = message_id
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECS) as smtp:
        smtp.send_message(msg, from_addr=SENDER, to_addrs=[*to, *cc])
    return message_id.strip("<>")


@mcp.tool()
def email_send(to: list[str], subject: str, body: str, cc: list[str] | None = None) -> str:
    """Send an email. `to` takes 1 to 5 addresses and `cc` up to 5."""
    cc = cc or []
    if not 1 <= len(to) <= 5:
        raise _fail("Provide between 1 and 5 recipients in 'to'.")
    if len(cc) > 5:
        raise _fail("Provide at most 5 addresses in 'cc'.")
    try:
        message_id = _send(to, subject, body, cc)
    except Exception:  # noqa: BLE001 - fixed message only
        raise _fail("The email could not be sent.") from None
    return f"Sent. message_id={message_id}"


if __name__ == "__main__":
    mcp.run()
