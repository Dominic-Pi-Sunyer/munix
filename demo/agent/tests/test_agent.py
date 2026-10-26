from conftest import text_reply, tool_call


def tool_messages(request):
    return [m for m in request["body"]["messages"] if m["role"] == "tool"]


def test_lists_tools_calls_them_and_prints_the_final_answer(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", {"text": "hi"}), text_reply("All done.")]
    result = run_agent(env={"MUNIX_BOSS_EMAIL": "chief@example.test", "MUNIX_WORKER_MODEL": "model-x"})

    assert result.returncode == 0, result.stderr
    assert len(fake_openai.requests) == 2

    first = fake_openai.requests[0]
    assert first["path"] == "/v1/chat/completions"
    assert first["auth"] == "Bearer sk-test-not-real"
    body = first["body"]
    assert body["model"] == "model-x"
    assert body["max_tokens"] == 4096
    by_name = {t["function"]["name"]: t for t in body["tools"]}
    assert set(by_name) == {"echo", "boom"}
    echo = by_name["echo"]
    assert echo["type"] == "function"
    assert echo["function"]["description"] == "Echo the text back."
    assert echo["function"]["parameters"]["properties"]["text"]["type"] == "string"
    assert echo["function"]["parameters"]["required"] == ["text"]
    system, user = body["messages"][:2]
    assert system["role"] == "system" and "chief@example.test" in system["content"]
    assert user == {"role": "user", "content": "do the task"}

    # The tool result is fed back as a tool message after the assistant's tool call.
    second = fake_openai.requests[1]["body"]["messages"]
    assert second[2]["role"] == "assistant" and second[2]["tool_calls"][0]["id"] == "call_1"
    assert second[3] == {"role": "tool", "tool_call_id": "call_1", "content": "echo: hi"}

    assert '→ echo {"text": "hi"}' in result.stdout
    assert "← echo: hi" in result.stdout
    assert result.stdout.rstrip().endswith("All done.")


def test_default_boss_and_model(fake_openai, run_agent):
    fake_openai.replies = [text_reply("ok")]
    result = run_agent()
    assert result.returncode == 0, result.stderr
    body = fake_openai.requests[0]["body"]
    assert body["model"] == "muse-spark-1.3"
    assert "boss@corp.example" in body["messages"][0]["content"]


def test_tool_errors_are_prefixed(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "boom", {}), text_reply("It failed.")]
    result = run_agent()

    assert result.returncode == 0, result.stderr
    (message,) = tool_messages(fake_openai.requests[1])
    assert message["content"].startswith("ERROR: ")
    assert "it broke" in message["content"]
    assert "← ERROR: " in result.stdout


def test_unknown_tool_is_an_error_message_not_a_crash(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "nope", {}), text_reply("Gave up.")]
    result = run_agent()

    assert result.returncode == 0, result.stderr
    (message,) = tool_messages(fake_openai.requests[1])
    assert message["content"].startswith("ERROR: ")


def test_malformed_arguments_get_an_error_tool_message(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", '{"text": '), text_reply("Sorry.")]
    result = run_agent()

    assert result.returncode == 0, result.stderr
    (message,) = tool_messages(fake_openai.requests[1])
    assert message["tool_call_id"] == "call_1"
    assert message["content"].startswith("ERROR: ")
    assert "Traceback" not in result.stderr
    assert result.stdout.rstrip().endswith("Sorry.")


def test_non_object_arguments_get_an_error_tool_message(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", "[1, 2]"), text_reply("Sorry.")]
    result = run_agent()

    assert result.returncode == 0, result.stderr
    (message,) = tool_messages(fake_openai.requests[1])
    assert message["content"].startswith("ERROR: ")


def test_max_steps_stops_the_loop(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", {"text": "again"})]  # repeats forever
    result = run_agent("--max-steps", "3")

    assert result.returncode != 0
    assert len(fake_openai.requests) == 3
    assert "Stopped after 3 steps" in result.stdout


def test_missing_api_key_exits_with_a_clear_message(fake_openai, run_agent):
    result = run_agent(env={"OPENAI_API_KEY": None})

    assert result.returncode != 0
    assert "OPENAI_API_KEY" in result.stderr
    assert "sk-" not in result.stdout + result.stderr
    assert fake_openai.requests == []


def test_results_are_single_line_and_truncated(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", {"text": "line1\nline2 " + "x" * 500}), text_reply("ok")]
    result = run_agent()

    arrow = [line for line in result.stdout.splitlines() if line.startswith("← ")]
    assert len(arrow) == 1
    assert len(arrow[0]) <= 2 + 200
    assert "line1 line2" in arrow[0]
