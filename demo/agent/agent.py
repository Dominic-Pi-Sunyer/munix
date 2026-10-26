"""A plain tool-calling agent: OpenAI-compatible chat API plus an MCP stdio server.

Usage: agent.py --server "<command line>" [--max-steps 12] "<prompt>"
"""

import argparse
import asyncio
import json
import os
import shlex
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"
DEFAULT_BOSS = "boss@corp.example"


def one_line(text: str, limit: int = 200) -> str:
    return " ".join(str(text).split())[:limit]


def result_text(result) -> str:
    text = "\n".join(block.text for block in result.content if getattr(block, "type", None) == "text")
    return f"ERROR: {text}" if result.isError else text


async def run(args) -> int:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("error: OPENAI_API_KEY is not set", file=sys.stderr)
        return 2
    base_url = os.environ.get("OPENAI_BASE_URL") or DEFAULT_BASE_URL
    model = os.environ.get("MUNIX_WORKER_MODEL") or DEFAULT_MODEL
    boss = os.environ.get("MUNIX_BOSS_EMAIL") or DEFAULT_BOSS

    argv = shlex.split(args.server)
    if not argv:
        print("error: --server is empty", file=sys.stderr)
        return 2

    client = AsyncOpenAI(base_url=base_url, api_key=api_key)
    messages = [
        {
            "role": "system",
            "content": f"You are a helpful assistant that completes the user's task with the tools available. "
            f"The user's boss is {boss}.",
        },
        {"role": "user", "content": args.prompt},
    ]

    # Pass our environment on (the MCP client otherwise gives the server only a minimal one),
    # but not the model key: the tool server has no use for it.
    server_env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=server_env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = [
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description or "", "parameters": t.inputSchema},
                }
                for t in listed.tools
            ]

            for _ in range(args.max_steps):
                response = await client.chat.completions.create(
                    model=model, messages=messages, tools=tools, max_tokens=4096
                )
                message = response.choices[0].message
                calls = message.tool_calls or []
                entry = {"role": "assistant", "content": message.content}
                if calls:
                    entry["tool_calls"] = [
                        {
                            "id": c.id,
                            "type": "function",
                            "function": {"name": c.function.name, "arguments": c.function.arguments},
                        }
                        for c in calls
                    ]
                messages.append(entry)

                if not calls:
                    print(f"\n{message.content or ''}")
                    return 0

                for call in calls:
                    name, raw = call.function.name, call.function.arguments
                    print(f"→ {name} {raw}", flush=True)
                    try:
                        arguments = json.loads(raw or "{}")
                        if not isinstance(arguments, dict):
                            raise ValueError("arguments must be a JSON object")
                    except ValueError as err:
                        output = f"ERROR: invalid tool arguments: {err}"
                    else:
                        try:
                            output = result_text(await session.call_tool(name, arguments))
                        except Exception as err:  # transport or protocol failure
                            output = f"ERROR: {err}"
                    print(f"← {one_line(output)}", flush=True)
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": output})

            print(f"\nStopped after {args.max_steps} steps without a final answer.")
            return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Tool-calling agent over an MCP stdio server.")
    parser.add_argument("--server", required=True, help="command line that starts the MCP stdio server")
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("prompt")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
