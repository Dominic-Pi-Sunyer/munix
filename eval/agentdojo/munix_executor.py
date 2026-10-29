"""Run AgentDojo tool calls through a real Munix Gate, via the `munix bridge` process (see BRIDGE.md).

Python never decides anything here. `BridgeClient` carries one task's calls to the bridge, `MunixToolsExecutor` runs a
tool on AgentDojo's environment only when the bridge asks for it (the Gate allowed the call), and `MunixStart` gives
every task its own bridge, so context trust and the ledger never carry over between tasks.
"""

import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
from ast import literal_eval
from collections.abc import Callable, Sequence
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # `python -I` does not put the script's directory on the path
    sys.path.insert(0, str(HERE))

import convert  # noqa: E402
ROOT = HERE.parents[1]
DEFAULT_BINARY = ROOT / "target" / "debug" / "munix"
DEFAULT_MANIFESTS = HERE / "manifests" / "banking"
DEFAULT_READ_TIMEOUT = 300.0  # seconds; the bridge may call the planner or reviewer model while we wait
MAX_ERROR_CHARS = 500

# One summary per finished task, in order. run.py saves it in the results JSON under "munix".
SUMMARIES: list[dict] = []


class BridgeError(RuntimeError):
    """The bridge died, timed out, or said something the protocol does not allow."""


class BridgeClient:
    """One `munix bridge` subprocess, for one task."""

    def __init__(
        self,
        manifests: Path | str = DEFAULT_MANIFESTS,
        ledger: Path | str = "ledger.jsonl",
        binary: Path | str | Sequence[str] = DEFAULT_BINARY,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        env: dict[str, str] | None = None,
        simulated_user: bool = False,
        plan_memory: Path | str | None = None,
        detector_url: str | None = None,
        detector_threshold: float | None = None,
    ) -> None:
        self.manifests = Path(manifests)
        self.ledger = Path(ledger)
        # A sequence is a command prefix (tests pass [python, fake_bridge.py]); a path is the munix binary.
        self.command = [str(c) for c in binary] if isinstance(binary, (list, tuple)) else [str(binary)]
        self.read_timeout = read_timeout
        self.env = env
        # With it, the bridge's Console approves a request only when every destination and selector traces to the
        # prompt, a store or a record at trust >= 80 (a stand-in for a careful human); without it, it always says no.
        self.simulated_user = simulated_user
        # Plan memory's directory (docs/plan-memory.md): a stored plan may replace the bridge's planner call.
        self.plan_memory = plan_memory
        # A prompt-injection detector's sidecar (invariant 7: it can only lower trust) and its flag threshold.
        self.detector_url = detector_url
        self.detector_threshold = detector_threshold
        self.calls = 0
        self.denials = 0
        self.tools_run = 0
        self._proc: subprocess.Popen | None = None
        self._lines: queue.Queue = queue.Queue()
        self._stderr_path = self.ledger.with_suffix(".stderr")
        self._stderr_file = None

    # -- process ----------------------------------------------------------------------------------------------

    def _spawn(self) -> None:
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        cmd = [*self.command, "bridge", "--manifests", str(self.manifests), "--ledger", str(self.ledger)]
        if self.simulated_user:
            cmd.append("--simulated-user")
        if self.plan_memory is not None:
            cmd += ["--plan-memory", str(self.plan_memory)]
        if self.detector_url is not None:
            cmd += ["--detector-url", self.detector_url]
        if self.detector_threshold is not None:
            cmd += ["--detector-threshold", str(self.detector_threshold)]
        env = {**os.environ, **(self.env or {})}
        self._stderr_file = open(self._stderr_path, "wb")
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr_file,
                env=env,
                cwd=ROOT,
            )
        except OSError as e:
            self.kill()
            raise BridgeError(f"cannot start the munix bridge ({cmd[0]}): {e}") from e
        threading.Thread(target=self._pump, args=(self._proc.stdout,), daemon=True).start()

    def _pump(self, stdout) -> None:
        try:
            for line in stdout:
                self._lines.put(line)
        finally:
            self._lines.put(None)  # end of output

    def _stderr_tail(self) -> str:
        try:
            return self._stderr_path.read_text(encoding="utf-8", errors="replace")[-500:].strip()
        except OSError:
            return ""

    def _fail(self, message: str) -> BridgeError:
        self.kill()
        tail = self._stderr_tail()
        return BridgeError(message + (f" (bridge stderr: {tail})" if tail else ""))

    def _send(self, message: dict) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise BridgeError("the bridge is not running")
        try:
            proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise self._fail(f"the bridge closed its input: {e}") from e

    def _read(self) -> dict:
        try:
            line = self._lines.get(timeout=self.read_timeout)
        except queue.Empty:
            raise self._fail(f"the bridge sent nothing for {self.read_timeout:g}s") from None
        if line is None:
            self._lines.put(None)
            code = self._proc.wait() if self._proc else None
            raise self._fail(f"the bridge exited (code {code}) while we waited for it")
        try:
            message = json.loads(line)
        except ValueError:
            raise self._fail(f"the bridge sent a line that is not JSON: {line[:200]!r}") from None
        if not isinstance(message, dict) or "op" not in message:
            raise self._fail(f"the bridge sent something that is not a protocol message: {line[:200]!r}")
        if message["op"] == "error":
            raise self._fail(f"the bridge reported an error: {message.get('message')}")
        return message

    def _expect(self, op: str) -> dict:
        message = self._read()
        if message["op"] != op:
            raise self._fail(f"expected {op!r} from the bridge, got {message['op']!r}")
        return message

    def kill(self) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc is not None:
            for pipe in (proc.stdin, proc.stdout):
                try:
                    if pipe is not None:
                        pipe.close()
                except OSError:
                    pass
        if self._stderr_file is not None:
            self._stderr_file.close()
            self._stderr_file = None

    # -- protocol ---------------------------------------------------------------------------------------------

    def start(self, prompt: str) -> dict:
        """Spawn the bridge and send the task. Returns the `started` message."""
        self._spawn()
        self._send({"op": "start", "prompt": prompt})
        return self._expect("started")

    def call(self, name: str, arguments: dict, serve: Callable[[str, dict], dict]) -> dict:
        """Send one tool call. `serve(name, arguments)` runs the tool when the Gate allows it and returns the
        `tool_result` body: `{"ok": True, "output": {...}}` or `{"ok": False, "error": "..."}`.
        Returns the bridge's `result` message (`text`, `is_error`)."""
        self.calls += 1
        self._send({"op": "call", "name": name, "arguments": arguments})
        while True:
            message = self._read()
            if message["op"] == "run_tool":
                if message.get("name") != name:
                    raise self._fail(f"the bridge asked to run {message.get('name')!r} during a call to {name!r}")
                self.tools_run += 1
                body = serve(name, message.get("arguments") or {})
                self._send({"op": "tool_result", **body})
            elif message["op"] == "result":
                if not isinstance(message.get("text"), str) or not isinstance(message.get("is_error"), bool):
                    raise self._fail(f"malformed result from the bridge: {message}")
                if message["is_error"]:
                    self.denials += 1
                return message
            else:
                raise self._fail(f"unexpected {message['op']!r} from the bridge during a call")

    def end(self) -> dict:
        """Close the task. Returns the `ended` message and waits for the process to exit."""
        self._send({"op": "end"})
        ended = self._expect("ended")
        proc = self._proc
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            raise self._fail("the bridge did not exit after `ended`") from None
        self.kill()
        return ended


class MunixSession:
    """The bridges of one run, one at a time. Shared by `MunixStart` and `MunixToolsExecutor`."""

    def __init__(
        self,
        ledger_dir: Path | str,
        tag: str = "run",
        manifests: Path | str = DEFAULT_MANIFESTS,
        binary: Path | str | Sequence[str] = DEFAULT_BINARY,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        env: dict[str, str] | None = None,
        simulated_user: bool = False,
        plan_memory: Path | str | None = None,
        detector_url: str | None = None,
        detector_threshold: float | None = None,
        suite: str | None = None,
    ) -> None:
        self.ledger_dir = Path(ledger_dir)
        self.tag = tag
        self.manifests = manifests
        self.binary = binary
        self.read_timeout = read_timeout
        self.env = env
        self.simulated_user = simulated_user
        self.plan_memory = plan_memory
        self.detector_url = detector_url
        self.detector_threshold = detector_threshold
        # Which suite's converters to use: given, else the manifests directory's name (manifests/<suite>).
        self.suite = suite or (Path(manifests).name if Path(manifests).name in convert.SUITES else None)
        self.tasks = 0
        self.client: BridgeClient | None = None
        self._record: dict | None = None
        # True when Munix could not start the current task (see MunixStart): no tool may run.
        self.refused = False

    def start_task(self, prompt: str) -> None:
        self.end_task()
        self.refused = False
        self.tasks += 1
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
        # The process id keeps two runs started in the same second (same tag) from writing one ledger file.
        ledger = self.ledger_dir / f"{self.tag}-p{os.getpid()}-{self.tasks:04d}-{digest}.jsonl"
        self._record = {"index": self.tasks, "prompt_sha256": digest, "ledger": str(ledger)}
        client = BridgeClient(
            self.manifests, ledger, self.binary, self.read_timeout, self.env, self.simulated_user, self.plan_memory,
            self.detector_url, self.detector_threshold,
        )
        self.client = client
        try:
            started = client.start(prompt)
        except BridgeError as e:
            self._record["error"] = str(e)
            self._finish()
            raise
        self._record["task"] = started.get("task")
        self._record["plan_steps"] = started.get("plan_steps")

    def end_task(self) -> None:
        """End the current task's bridge, if any, and record its summary. Never raises: a bridge that fails to
        end is recorded as an error in the summary."""
        client, record = self.client, self._record
        if client is None or record is None:
            return
        if "error" not in record:
            try:
                ended = client.end()
                for key in ("context_trust", "ledger_entries", "ledger_verified", "takeover", "supervisor_usage", "plan"):
                    record[key] = ended.get(key)
            except BridgeError as e:
                record["error"] = str(e)
        self._finish()

    def _finish(self) -> None:
        client, record = self.client, self._record
        if client is not None and record is not None:
            client.kill()
            record["calls"] = client.calls
            record["denials"] = client.denials
            record["tools_run"] = client.tools_run
            SUMMARIES.append(record)
        self.client = None
        self._record = None

    def close(self) -> None:
        self.end_task()

    def __enter__(self) -> "MunixSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class MunixStart(BasePipelineElement):
    """Starts a fresh bridge for every task, right after `InitQuery`. Its query is the user's prompt."""

    def __init__(self, session: MunixSession) -> None:
        self.session = session

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        try:
            self.session.start_task(query)
        except BridgeError:
            # Munix could not start the task: the planner wrote no valid plan, or the bridge failed. The error is in
            # SUMMARIES, and the task runs with every tool call refused, as `munix run` would refuse it.
            self.session.refused = True
        return query, runtime, env, messages, extra_args


def _short(text: str) -> str:
    return text if len(text) <= MAX_ERROR_CHARS else text[:MAX_ERROR_CHARS] + "..."


class MunixToolsExecutor(ToolsExecutor):
    """Like `ToolsExecutor`, but every call goes to the Gate first. The tool runs on the environment only when the
    bridge asks for it, and the model sees exactly what the bridge returns."""

    def __init__(self, session: MunixSession) -> None:
        super().__init__()
        self.session = session

    def _serve(self, runtime: FunctionsRuntime, env: Env) -> Callable[[str, dict], dict]:
        def serve(name: str, arguments: dict) -> dict:
            result, error = runtime.run_function(env, name, arguments)
            if error is not None:
                return {"ok": False, "error": _short(error)}
            try:
                return {"ok": True, "output": convert.to_fields(name, result, env, getattr(self.session, "suite", None))}
            except (KeyError, ValueError, TypeError) as e:
                return {"ok": False, "error": _short(f"{type(e).__name__}: {e}")}

        return serve

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        def failure(tool_call, text: str) -> ChatToolResultMessage:
            return ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string("")],
                tool_call_id=tool_call.id,
                tool_call=tool_call,
                error=text,
            )

        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(failure(tool_call, "Empty function name provided. Provide a valid function name."))
                continue
            if tool_call.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(failure(tool_call, f"Invalid tool {tool_call.function} provided."))
                continue

            # Same normalization as ToolsExecutor: a list sent as a string becomes a list.
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            if getattr(self.session, "refused", False):  # oracle.py passes a bare namespace
                tool_call_results.append(failure(tool_call, "denied: not permitted"))
                continue
            client = self.session.client
            if client is None:
                raise BridgeError("no bridge is running: MunixStart must come before MunixToolsExecutor")
            # An omitted optional argument and an explicit null mean the same to AgentDojo's functions; the Gate's
            # schema has no null, so null arguments are dropped rather than sent.
            arguments = {k: v for k, v in tool_call.args.items() if v is not None}
            outcome = client.call(tool_call.function, arguments, self._serve(runtime, env))
            if outcome["is_error"]:
                tool_call_results.append(failure(tool_call, outcome["text"]))
            else:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(outcome["text"])],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=None,
                    )
                )
        return query, runtime, env, [*messages, *tool_call_results], extra_args
