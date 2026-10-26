import pytest
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
    answer, cost_line = result.stdout.rstrip().rsplit("\n", 1)
    assert answer.endswith("All done.")
    assert cost_line.startswith("tokens: prompt 2 · completion 2 (reasoning 0) · calls 2 · est. cost $")


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
    assert result.stdout.rstrip().splitlines()[-2] == "Sorry."


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


# --- reasoning effort -------------------------------------------------------


def test_effort_defaults_to_low(fake_openai, run_agent):
    fake_openai.replies = [text_reply("ok")]
    result = run_agent()
    assert result.returncode == 0, result.stderr
    assert fake_openai.requests[0]["body"]["reasoning_effort"] == "low"


def test_effort_comes_from_env(fake_openai, run_agent):
    fake_openai.replies = [text_reply("ok")]
    result = run_agent(env={"MUNIX_WORKER_EFFORT": "high"})
    assert result.returncode == 0, result.stderr
    assert fake_openai.requests[0]["body"]["reasoning_effort"] == "high"


def test_effort_flag_beats_env(fake_openai, run_agent):
    fake_openai.replies = [text_reply("ok")]
    result = run_agent("--reasoning-effort", "minimal", env={"MUNIX_WORKER_EFFORT": "high"})
    assert result.returncode == 0, result.stderr
    assert fake_openai.requests[0]["body"]["reasoning_effort"] == "minimal"


def test_effort_reaches_every_call(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", {"text": "hi"}), text_reply("ok")]
    result = run_agent("--reasoning-effort", "xhigh")
    assert result.returncode == 0, result.stderr
    assert [r["body"]["reasoning_effort"] for r in fake_openai.requests] == ["xhigh", "xhigh"]


@pytest.mark.parametrize("effort", ["minimal", "low", "medium", "high", "xhigh", "max"])
def test_every_allowed_effort_is_accepted(fake_openai, run_agent, effort):
    fake_openai.replies = [text_reply("ok")]
    result = run_agent("--reasoning-effort", effort)
    assert result.returncode == 0, result.stderr
    assert fake_openai.requests[0]["body"]["reasoning_effort"] == effort


@pytest.mark.parametrize("via", ["flag", "env"])
def test_invalid_effort_exits_2_without_calling_the_model(fake_openai, run_agent, via):
    fake_openai.replies = [text_reply("ok")]
    if via == "flag":
        result = run_agent("--reasoning-effort", "turbo")
    else:
        result = run_agent(env={"MUNIX_WORKER_EFFORT": "turbo"})
    assert result.returncode == 2
    assert "turbo" in result.stderr and "minimal" in result.stderr
    assert fake_openai.requests == []


# --- token and cost counter -------------------------------------------------


def test_cost_line_for_one_call_with_default_prices(fake_openai, run_agent):
    fake_openai.replies = [text_reply("Done.")]
    fake_openai.usages = [
        {
            "prompt_tokens": 1000,
            "completion_tokens": 500,
            "total_tokens": 1500,
            "completion_tokens_details": {"reasoning_tokens": 200},
        }
    ]
    result = run_agent()
    assert result.returncode == 0, result.stderr
    # 1000 * 1.25 / 1e6 + 500 * 4.25 / 1e6 = 0.00125 + 0.002125 = 0.003375
    expected = "tokens: prompt 1000 · completion 500 (reasoning 200) · calls 1 · est. cost $0.0034"
    assert result.stdout.rstrip().splitlines()[-1] == expected


def test_usage_is_summed_across_calls_and_missing_fields_count_as_zero(fake_openai, run_agent):
    fake_openai.replies = [
        tool_call("call_1", "echo", {"text": "a"}),
        tool_call("call_2", "echo", {"text": "b"}),
        tool_call("call_3", "echo", {"text": "c"}),
        text_reply("Done."),
    ]
    fake_openai.usages = [
        {"prompt_tokens": 100_000, "completion_tokens": 20_000, "completion_tokens_details": {"reasoning_tokens": 5_000}},
        {"prompt_tokens": 200_000},  # no completion or reasoning fields
        {"completion_tokens": 10_000, "completion_tokens_details": {}},  # no prompt, no reasoning
        {"prompt_tokens": 40_100, "completion_tokens": 5_000, "completion_tokens_details": {"reasoning_tokens": 1_000}},
    ]
    result = run_agent()
    assert result.returncode == 0, result.stderr
    # prompt 340100, completion 35000, reasoning 6000: 0.425125 + 0.14875 = 0.573875, rounds to 0.5739
    expected = "tokens: prompt 340100 · completion 35000 (reasoning 6000) · calls 4 · est. cost $0.5739"
    assert result.stdout.rstrip().splitlines()[-1] == expected


def test_a_reply_with_no_usage_at_all_counts_as_a_call_with_zero_tokens(fake_openai, run_agent):
    fake_openai.replies = [text_reply("Done.")]
    fake_openai.usages = [None]
    result = run_agent()
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip().splitlines()[-1] == (
        "tokens: prompt 0 · completion 0 (reasoning 0) · calls 1 · est. cost $0.0000"
    )


def test_prices_come_from_env(fake_openai, run_agent):
    fake_openai.replies = [text_reply("Done.")]
    fake_openai.usages = [{"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000}]
    result = run_agent(env={"MUNIX_PRICE_INPUT_PER_M": "2", "MUNIX_PRICE_OUTPUT_PER_M": "10"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip().splitlines()[-1] == (
        "tokens: prompt 1000000 · completion 1000000 (reasoning 0) · calls 1 · est. cost $12.0000"
    )


def test_the_cost_line_is_also_printed_when_the_step_limit_is_hit(fake_openai, run_agent):
    fake_openai.replies = [tool_call("call_1", "echo", {"text": "again"})]
    result = run_agent("--max-steps", "2")
    assert result.returncode != 0
    assert "Stopped after 2 steps" in result.stdout
    assert result.stdout.rstrip().splitlines()[-1] == (
        "tokens: prompt 2 · completion 2 (reasoning 0) · calls 2 · est. cost $0.0000"
    )


@pytest.mark.parametrize(
    "env",
    [
        {"MUNIX_PRICE_INPUT_PER_M": "cheap"},
        {"MUNIX_PRICE_OUTPUT_PER_M": "cheap"},
        {"MUNIX_PRICE_INPUT_PER_M": "-1"},
        {"MUNIX_PRICE_OUTPUT_PER_M": "nan"},
        {"MUNIX_PRICE_INPUT_PER_M": "inf"},
    ],
)
def test_bad_price_exits_2_without_calling_the_model(fake_openai, run_agent, env):
    fake_openai.replies = [text_reply("ok")]
    result = run_agent(env=env)
    assert result.returncode == 2
    assert "MUNIX_PRICE_" in result.stderr
    assert fake_openai.requests == []
