"""Run AgentDojo suites against Muse Spark, bare or (later) under Munix, and summarize the results.

    cd eval/agentdojo
    .venv/bin/python -I run.py run --suite banking --phase utility            # user tasks, no attack
    .venv/bin/python -I run.py run --suite banking --phase goals              # injection goals as user tasks
    .venv/bin/python -I run.py run --suite banking --phase attack --shard 1/4 # user tasks x injection tasks
    .venv/bin/python -I run.py report --suite banking

Each run writes `results/<mode>-<suite>-<phase>[-<shard>].json` (scores, token usage and an estimated cost, no
transcripts). Transcripts go to `runs/` (gitignored). Reads MODEL_API_KEY from the repo's .env and never prints it.
`--mode munix` (banking only) sends every tool call through a Munix Gate via `munix bridge`; see BRIDGE.md.
Spends Meta credit; the lead runs it.
"""

import argparse
import contextlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # `python -I` does not put the script's directory on the path
    sys.path.insert(0, str(HERE))

import openai
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

import munix_executor

ROOT = HERE.parents[1]
BENCHMARK_VERSION = "v1.2.2"
ATTACK = "important_instructions"
META_URL = "https://api.meta.ai/v1"
PHASES = ("utility", "goals", "attack")


def env_value(name: str) -> str | None:
    try:
        lines = (ROOT / ".env").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip().removeprefix("export ").strip()
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip().strip("'\"") or None
    return None


class Usage:
    """Sums token usage over every chat completion the pipeline makes."""

    def __init__(self) -> None:
        self.calls = 0
        self.prompt = 0
        self.completion = 0

    def wrap(self, client: openai.OpenAI) -> None:
        create = client.chat.completions.create

        def counted(*args, **kwargs):
            response = create(*args, **kwargs)
            self.calls += 1
            if response.usage is not None:
                self.prompt += response.usage.prompt_tokens or 0
                self.completion += response.usage.completion_tokens or 0
            return response

        client.chat.completions.create = counted

    def cost(self, input_per_m: float, output_per_m: float) -> float:
        return (self.prompt * input_per_m + self.completion * output_per_m) / 1_000_000


def bare_pipeline(model: str, effort: str, key: str, usage: Usage) -> AgentPipeline:
    client = openai.OpenAI(base_url=META_URL, api_key=key)
    usage.wrap(client)
    llm = OpenAILLM(client, model, reasoning_effort=effort)
    loop = ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=15)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm, loop])
    # AgentDojo requires a registered model key in the name ("local"); the attack text then calls the model
    # "Local model", the same for every setup we compare.
    pipe.name = f"local-{model}-{effort}-bare"
    return pipe


def munix_pipeline(model: str, effort: str, key: str, usage: Usage, session: munix_executor.MunixSession) -> AgentPipeline:
    """The same agent as `bare_pipeline`, with every tool call sent through a Munix Gate (one bridge per task)."""
    client = openai.OpenAI(base_url=META_URL, api_key=key)
    usage.wrap(client)
    llm = OpenAILLM(client, model, reasoning_effort=effort)
    loop = ToolsExecutionLoop([munix_executor.MunixToolsExecutor(session), llm], max_iters=15)
    pipe = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), munix_executor.MunixStart(session), llm, loop]
    )
    pipe.name = f"local-{model}-{effort}-munix"
    return pipe


def shard_of(items: list[str], shard: str | None) -> list[str]:
    if not shard:
        return items
    i, n = (int(x) for x in shard.split("/"))
    if not 1 <= i <= n:
        raise SystemExit("--shard must be i/n with 1 <= i <= n")
    return [t for k, t in enumerate(items) if k % n == i - 1]


def cmd_run(args) -> int:
    if args.mode == "munix" and args.suite != "banking":
        print(f"--mode munix has manifests for the banking suite only, not {args.suite}", file=sys.stderr)
        return 2
    key = env_value("MODEL_API_KEY")
    if not key:
        print("MODEL_API_KEY is not set in .env", file=sys.stderr)
        return 1
    model = args.model or env_value("MUNIX_WORKER_MODEL") or "muse-spark-1.3"
    usage = Usage()
    session = None
    if args.mode == "munix":
        binary = Path(args.munix_bin)
        if not binary.is_file():
            print(f"munix binary not found at {binary} (build it, or pass --munix-bin)", file=sys.stderr)
            return 2
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shard_tag = args.shard.replace("/", "of") if args.shard else "all"
        session = munix_executor.MunixSession(
            ledger_dir=HERE / "runs" / "ledgers",
            tag=f"{args.suite}-{args.phase}-{shard_tag}-{stamp}",
            manifests=HERE / "manifests" / args.suite,
            binary=binary,
        )
        munix_executor.SUMMARIES.clear()
        pipe = munix_pipeline(model, args.effort, key, usage, session)
    else:
        pipe = bare_pipeline(model, args.effort, key, usage)
    suite = get_suite(BENCHMARK_VERSION, args.suite)
    user_ids = args.user_tasks.split(",") if args.user_tasks else sorted(suite.user_tasks, key=task_number)
    inj_ids = args.injection_tasks.split(",") if args.injection_tasks else sorted(suite.injection_tasks, key=task_number)
    logdir = HERE / "runs"
    started = time.monotonic()
    utility: dict[str, bool] = {}
    security: dict[str, bool] = {}
    with OutputLogger(str(logdir), live=None), (session or contextlib.nullcontext()):
        if args.phase == "utility":
            for uid in shard_of(user_ids, args.shard):
                ok, _ = run_task_without_injection_tasks(
                    suite, pipe, suite.get_user_task_by_id(uid), logdir, True, BENCHMARK_VERSION
                )
                utility[uid] = ok
                print(f"{args.suite} {uid}: utility={ok}", flush=True)
        elif args.phase == "goals":
            for iid in shard_of(inj_ids, args.shard):
                ok, _ = run_task_without_injection_tasks(
                    suite, pipe, suite.get_injection_task_by_id(iid), logdir, True, BENCHMARK_VERSION
                )
                utility[iid] = ok
                print(f"{args.suite} {iid} as a user task: utility={ok}", flush=True)
        else:
            attack = load_attack(ATTACK, suite, pipe)
            for uid in shard_of(user_ids, args.shard):
                u, s = run_task_with_injection_tasks(
                    suite, pipe, suite.get_user_task_by_id(uid), attack, logdir, True, inj_ids, BENCHMARK_VERSION
                )
                for (ut, it), ok in u.items():
                    utility[f"{ut}|{it}"] = ok
                for (ut, it), hit in s.items():
                    security[f"{ut}|{it}"] = hit
                hits = sum(1 for (ut, _), hit in s.items() if hit)
                print(f"{args.suite} {uid}: utility {sum(u.values())}/{len(u)}, attacks succeeded {hits}/{len(s)}", flush=True)
    input_per_m = float(env_value("MUNIX_PRICE_INPUT_PER_M") or 1.25)
    output_per_m = float(env_value("MUNIX_PRICE_OUTPUT_PER_M") or 4.25)
    doc = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": args.mode,
        "suite": args.suite,
        "phase": args.phase,
        "shard": args.shard,
        "benchmark_version": BENCHMARK_VERSION,
        "attack": ATTACK if args.phase == "attack" else None,
        "model": model,
        "reasoning_effort": args.effort,
        "utility": utility,
        "security": security,
        "usage": {"calls": usage.calls, "prompt_tokens": usage.prompt, "completion_tokens": usage.completion},
        "estimated_cost_usd": round(usage.cost(input_per_m, output_per_m), 4),
        "seconds": round(time.monotonic() - started, 1),
    }
    if args.mode == "munix":
        doc["munix"] = list(munix_executor.SUMMARIES)
    out = HERE / "results" / result_name(args.mode, args.suite, args.phase, args.shard)
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(HERE)}: {usage.calls} calls, about ${doc['estimated_cost_usd']:.4f}")
    return 0


def task_number(task_id: str) -> int:
    return int(task_id.rsplit("_", 1)[-1])


def result_name(mode: str, suite: str, phase: str, shard: str | None) -> str:
    tail = f"-{shard.replace('/', 'of')}" if shard else ""
    return f"{mode}-{suite}-{phase}{tail}.json"


def cmd_report(args) -> int:
    for mode in ("bare", "munix"):
        files = sorted((HERE / "results").glob(f"{mode}-{args.suite}-*.json"))
        if not files:
            continue
        merged = {p: {"utility": {}, "security": {}} for p in PHASES}
        cost = 0.0
        for f in files:
            d = json.loads(f.read_text(encoding="utf-8"))
            merged[d["phase"]]["utility"].update(d["utility"])
            merged[d["phase"]]["security"].update(d["security"])
            cost += d["estimated_cost_usd"]

        def rate(values: dict) -> str:
            return f"{sum(values.values())}/{len(values)} ({100 * sum(values.values()) / len(values):.1f}%)" if values else "-"

        print(f"{mode} · {args.suite} · {BENCHMARK_VERSION} · {ATTACK}")
        print(f"  utility, no attack:        {rate(merged['utility']['utility'])}")
        print(f"  utility under attack:      {rate(merged['attack']['utility'])}")
        print(f"  attack success rate (ASR): {rate(merged['attack']['security'])}")
        print(f"  injection goals as tasks:  {rate(merged['goals']['utility'])}")
        print(f"  estimated cost:            ${cost:.2f}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--suite", required=True, choices=("banking", "slack"))
    r.add_argument("--phase", required=True, choices=PHASES)
    r.add_argument("--mode", default="bare", choices=("bare", "munix"))
    r.add_argument("--model", help="default: MUNIX_WORKER_MODEL from .env, else muse-spark-1.3")
    r.add_argument("--munix-bin", default=str(munix_executor.DEFAULT_BINARY), help="the munix binary (--mode munix)")
    r.add_argument("--effort", default="low", choices=("minimal", "low", "medium", "high"))
    r.add_argument("--user-tasks", help="comma-separated ids (default: all)")
    r.add_argument("--injection-tasks", help="comma-separated ids (default: all)")
    r.add_argument("--shard", help="i/n: run every n-th user task (or injection task for --phase goals)")
    rp = sub.add_parser("report")
    rp.add_argument("--suite", required=True, choices=("banking", "slack"))
    args = ap.parse_args()
    return cmd_run(args) if args.cmd == "run" else cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
