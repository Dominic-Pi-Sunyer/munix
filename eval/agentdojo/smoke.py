"""Smoke test: can AgentDojo drive Muse Spark through the Meta API? One benign task, no attack, no Munix.

    cd eval/agentdojo && .venv/bin/python -I smoke.py [suite] [user_task]

Reads MODEL_API_KEY from the repo's .env and never prints it. Spends a little Meta credit (one task).
"""

import sys
from pathlib import Path

import openai
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.benchmark import benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import credit  # noqa: E402

# About what one benign task costs; smoke.py does not count tokens.
SMOKE_COST = 0.03
BENCHMARK_VERSION = "v1.2.2"


def env_value(name: str) -> str | None:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip().removeprefix("export ").strip()
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip().strip("'\"") or None
    return None


def main() -> int:
    suite_name = sys.argv[1] if len(sys.argv) > 1 else "banking"
    user_task = sys.argv[2] if len(sys.argv) > 2 else "user_task_3"
    key = env_value("MODEL_API_KEY")
    if not key:
        print("MODEL_API_KEY is not set in .env", file=sys.stderr)
        return 1
    try:
        credit.check()
    except credit.CreditError as e:
        print(f"credit: {e}", file=sys.stderr)
        return 2
    credit.charge(SMOKE_COST)
    model = env_value("MUNIX_WORKER_MODEL") or "muse-spark-1.3"
    client = openai.OpenAI(base_url="https://api.meta.ai/v1", api_key=key)
    llm = OpenAILLM(client, model, reasoning_effort="low")
    loop = ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=15)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm, loop])
    pipe.name = f"local-{model}-bare"
    suite = get_suite(BENCHMARK_VERSION, suite_name)
    logdir = Path(__file__).resolve().parent / "runs"
    with OutputLogger(str(logdir), live=None):
        results = benchmark_suite_without_injections(
            pipe, suite, logdir=logdir, force_rerun=True, user_tasks=[user_task], benchmark_version=BENCHMARK_VERSION
        )
    for task, ok in results["utility_results"].items():
        print(f"{suite_name} {task[0]}: utility={ok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
