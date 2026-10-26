import email
import json
import socket

import pytest
from conftest import EXPECTED_RENDER
from mcp.server.fastmcp.exceptions import ToolError

import server


def call(coro_or_value):
    import asyncio

    return asyncio.run(coro_or_value) if asyncio.iscoroutine(coro_or_value) else coro_or_value


def test_web_open_renders_contract_format(env):
    assert call(server.web_open("http://127.0.0.1:8080/reviews/gaming-monitor")) == EXPECTED_RENDER


def test_links_section_is_last_one_url_per_line_deduped(env):
    out = call(server.web_open("http://127.0.0.1:8080/x"))
    head, _, links = out.partition("\nLinks:\n")
    assert links.splitlines() == ["http://127.0.0.1:8080/specs", "http://127.0.0.1:8080/"]
    assert out.startswith("Title: ")


def test_render_optional_sections():
    page = {
        "title": "T",
        "sections": [{"heading": "Sec", "text": "Body"}],
        "product": {"name": "Widget", "price": "$9"},
        "items": [{"name": "A", "price": "1"}, {"name": "B", "price": "2"}],
    }
    assert server.render_page(page).splitlines() == [
        "Title: T",
        "Sec",
        "Body",
        "name: Widget",
        "price: $9",
        "A | 1",
        "B | 2",
        "Links:",
    ]


def test_web_speed_error_json_becomes_fixed_tool_error(env):
    with pytest.raises(ToolError) as err:
        call(server.web_open("http://blocked.example/"))
    assert "SECRET-REMOTE-TEXT" not in str(err.value)
    assert "BLOCKED" not in str(err.value)
    assert "could not be opened" in str(err.value)


def test_web_speed_launch_failure_is_fixed_tool_error(env, monkeypatch):
    monkeypatch.setenv("WEBSPEED_COMMAND", "/nonexistent/python /nonexistent/server.py")
    with pytest.raises(ToolError) as err:
        call(server.web_open("http://127.0.0.1:8080/"))
    assert str(err.value) == "The page could not be opened."


def test_email_delivered_with_recipients_subject_body(env, smtp):
    out = server.email_send(["a@corp.example", "b@corp.example"], "Monitor summary", "Short body.", cc=["c@corp.example"])
    assert out.startswith("Sent. message_id=")
    assert len(smtp.messages) == 1
    got = smtp.messages[0]
    assert got["from"] == "agent@demo.local"
    assert got["rcpts"] == ["a@corp.example", "b@corp.example", "c@corp.example"]
    msg = email.message_from_string(got["data"])
    assert msg["Subject"] == "Monitor summary"
    assert msg["To"] == "a@corp.example, b@corp.example"
    assert msg["Cc"] == "c@corp.example"
    assert msg.get_payload().strip() == "Short body."
    assert out == f"Sent. message_id={msg['Message-ID'].strip('<>')}"


@pytest.mark.parametrize("endpoint", ["smtp.example.com:25", "10.0.0.5:1025", "8.8.8.8:25", "127.0.0.1.evil.com:25", "nonsense"])
def test_non_loopback_smtp_refused_and_nothing_sent(env, smtp, monkeypatch, endpoint):
    monkeypatch.setenv("MUNIX_SMTP", endpoint)
    with pytest.raises(ToolError) as err:
        server.email_send(["a@corp.example"], "s", "b")
    assert str(err.value) == "The email could not be sent."
    assert smtp.messages == []


def test_non_loopback_refused_before_any_connection(env, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not connect")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setenv("MUNIX_SMTP", "mail.example.com:25")
    with pytest.raises(ToolError):
        server.email_send(["a@corp.example"], "s", "b")


@pytest.mark.parametrize("to", [[], ["a@x.example"] * 6])
def test_to_count_limits(env, smtp, to):
    with pytest.raises(ToolError):
        server.email_send(to, "s", "b")
    assert smtp.messages == []


def test_cc_count_limit(env, smtp):
    with pytest.raises(ToolError):
        server.email_send(["a@x.example"], "s", "b", cc=["c@x.example"] * 6)
    assert smtp.messages == []


def test_five_to_and_five_cc_allowed(env, smtp):
    server.email_send([f"t{i}@x.example" for i in range(5)], "s", "b", cc=[f"c{i}@x.example" for i in range(5)])
    assert len(smtp.messages[0]["rcpts"]) == 10


def test_header_injection_rejected(env, smtp):
    with pytest.raises(ToolError):
        server.email_send(["a@x.example"], "hi\r\nBcc: evil@x.example", "b")
    assert smtp.messages == []


def test_smtp_connection_failure_is_fixed_error(env, monkeypatch):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    monkeypatch.setenv("MUNIX_SMTP", f"127.0.0.1:{port}")
    with pytest.raises(ToolError) as err:
        server.email_send(["a@x.example"], "s", "b")
    assert str(err.value) == "The email could not be sent."


def test_exposes_exactly_two_tools():
    tools = call(server.mcp.list_tools())
    assert sorted(t.name for t in tools) == ["email_send", "web_open"]
    schema = {t.name: t.inputSchema for t in tools}
    assert schema["web_open"]["required"] == ["url"]
    assert sorted(schema["email_send"]["required"]) == ["body", "subject", "to"]


def test_web_speed_registry_sync_is_always_off(monkeypatch):
    monkeypatch.setenv("WEB_SPEED_REGISTRY_SYNC", "true")
    assert server._webspeed_params().env["WEB_SPEED_REGISTRY_SYNC"] == "false"
