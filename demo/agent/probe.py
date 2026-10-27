#!/usr/bin/env python3
"""Sandbox escape probe for Munix (design spec section 11, item 12).

Runs INSIDE the Munix container as the agent command:
  munix run --plan examples/demo-plan.yaml --prompt "probe" -- python /agent/probe.py

Python stdlib only. Never calls an allowed model and never prints secret values.
stdout is the MCP channel, so all output goes to stderr and the process exits 0.
"""

from dataclasses import dataclass, field
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

NETWORK_TIMEOUT_S = 2.0
DEFAULT_PROBE_HOST = "192.168.5.2"
PLACEHOLDER_API_KEY = "munix-gateway"
DISALLOWED_MODEL = "munix-probe-not-allowed"
MAX_SCAN_FILES = 5000
MAX_FILE_BYTES = 1024 * 1024

# Built at run time (a call, which the compiler can't fold into one constant) so neither this file nor its .pyc
# matches its own key scan when /agent is walked.
MODEL_KEY_MARKER = b"".join([b"MODEL_API_", b"KEY="])
SK_TOKEN_RE = re.compile(rb"sk" + rb"-\w{20,}")
SECRET_ENV_SUBSTRINGS = ("KEY", "TOKEN", "SECRET")
# Set by the python base image, not by Munix: GPG_KEY is the public fingerprint of Python's release-signing key.
BASE_IMAGE_ENV = ("GPG_KEY",)


def default_tcp_connect(host: str, port: int, timeout: float = NETWORK_TIMEOUT_S) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def default_resolve(host: str, port: int) -> list:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(NETWORK_TIMEOUT_S)
    try:
        return socket.getaddrinfo(host, port)
    finally:
        socket.setdefaulttimeout(old_timeout)


def default_http_request(
    method: str,
    url: str,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = NETWORK_TIMEOUT_S,
) -> int | None:
    req = urllib.request.Request(url, data=body, headers=dict(headers or {}), method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as err:
        return int(err.code)
    except OSError:
        return None


def default_iter_scan_files() -> Iterable[tuple[str, int]]:
    """Yield (path, size_bytes) for /agent, /munix, /tmp recursively and / top-level, skipping /proc and /sys."""
    seen: set[str] = set()
    for root in ("/agent", "/munix", "/tmp"):
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if not os.path.join(dirpath, d).startswith(("/proc", "/sys"))
            ]
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if full in seen or full.startswith(("/proc", "/sys")):
                    continue
                seen.add(full)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if os.path.isfile(full) and not os.path.islink(full):
                    yield full, st.st_size

    try:
        top_entries = sorted(os.listdir("/"))
    except OSError:
        top_entries = []
    for name in top_entries:
        full = "/" + name
        if full in seen or full in ("/proc", "/sys") or full.startswith(("/proc/", "/sys/")):
            continue
        seen.add(full)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if os.path.isfile(full) and not os.path.islink(full):
            yield full, st.st_size


def default_read_bytes(path: str, max_bytes: int = MAX_FILE_BYTES) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return None


def default_try_write(directory: str) -> bool:
    probe_path = os.path.join(directory, f".munix_probe_{os.getpid()}")
    try:
        fd = os.open(probe_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            os.unlink(probe_path)
        except OSError:
            pass
        return True
    except OSError:
        return False


def default_path_exists(path: str) -> bool:
    return os.path.lexists(path)


def default_list_dir(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


@dataclass
class ProbeHelpers:
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    tcp_connect: Callable[[str, int, float], bool] = default_tcp_connect
    resolve: Callable[[str, int], list] = default_resolve
    http_request: Callable[[str, str, bytes | None, Mapping[str, str] | None, float], int | None] = (
        default_http_request
    )
    iter_scan_files: Callable[[], Iterable[tuple[str, int]]] = default_iter_scan_files
    read_bytes: Callable[[str, int], bytes | None] = default_read_bytes
    try_write: Callable[[str], bool] = default_try_write
    path_exists: Callable[[str], bool] = default_path_exists
    list_dir: Callable[[str], list[str]] = default_list_dir


def check_internet_tcp(h: ProbeHelpers) -> tuple[str, str]:
    targets = (("1.1.1.1", 443), ("8.8.8.8", 53))
    opened = [f"{host}:{port}" for host, port in targets if h.tcp_connect(host, port, NETWORK_TIMEOUT_S)]
    if opened:
        return "FAIL", f"connected to {', '.join(opened)}"
    return "PASS", "1.1.1.1:443 and 8.8.8.8:53 blocked"


def check_dns(h: ProbeHelpers) -> tuple[str, str]:
    try:
        res = h.resolve("example.com", 443)
    except OSError:
        return "PASS", "example.com resolution failed as expected"
    if res:
        return "FAIL", "example.com resolved inside sandbox"
    return "PASS", "example.com returned no addresses"


def check_host_services(h: ProbeHelpers) -> tuple[str, str]:
    gw = (h.environ.get("MUNIX_PROBE_HOST") or DEFAULT_PROBE_HOST).strip() or DEFAULT_PROBE_HOST
    hosts = [gw]
    if "host.docker.internal" not in hosts:
        hosts.append("host.docker.internal")
    ports = (1025, 8025, 8080)
    opened = [
        f"{host}:{port}"
        for host in hosts
        for port in ports
        if h.tcp_connect(host, port, NETWORK_TIMEOUT_S)
    ]
    if opened:
        return "FAIL", f"reached host service(s): {', '.join(opened)}"
    return "PASS", f"ports 1025, 8025, 8080 unreachable on {', '.join(hosts)}"


def check_relay_scope(h: ProbeHelpers) -> tuple[str, str]:
    base = (h.environ.get("OPENAI_BASE_URL") or "").strip().rstrip("/")
    parsed = urlsplit(base)
    host = parsed.hostname
    port = parsed.port
    if not base or not host or not port:
        return "FAIL", "OPENAI_BASE_URL is missing or has no host:port"

    relay_open = h.tcp_connect(host, port, NETWORK_TIMEOUT_S)
    relay_info = f"relay {host}:{port} {'reachable' if relay_open else 'unreachable'} (INFO)"

    models_status = h.http_request("GET", f"{base}/models", None, None, NETWORK_TIMEOUT_S)
    payload = json.dumps(
        {"model": DISALLOWED_MODEL, "messages": [{"role": "user", "content": "x"}]}
    ).encode("utf-8")
    chat_status = h.http_request(
        "POST",
        f"{base}/chat/completions",
        payload,
        {"Content-Type": "application/json"},
        NETWORK_TIMEOUT_S,
    )
    extra_ports = (22, 80, 8080)
    open_extra = [str(p) for p in extra_ports if h.tcp_connect(host, p, NETWORK_TIMEOUT_S)]

    failures: list[str] = []
    if models_status != 404:
        failures.append(f"GET /models status={models_status} (expected 404)")
    if chat_status not in (400, 403):
        failures.append(f"POST unallowed model status={chat_status} (expected 400/403)")
    if open_extra:
        failures.append(f"extra relay port(s) open: {','.join(open_extra)}")

    if failures:
        return "FAIL", f"{relay_info}; " + "; ".join(failures)
    return (
        "PASS",
        f"{relay_info}; GET /models=404; POST unallowed model={chat_status}; ports 22,80,8080 closed",
    )


def check_keys_in_env(h: ProbeHelpers) -> tuple[str, str]:
    matching = sorted(
        name
        for name in h.environ
        if any(part in name.upper() for part in SECRET_ENV_SUBSTRINGS)
    )
    other_names = [name for name in matching if name != "OPENAI_API_KEY" and name not in BASE_IMAGE_ENV]
    openai_val = h.environ.get("OPENAI_API_KEY")

    problems: list[str] = []
    if openai_val != PLACEHOLDER_API_KEY:
        problems.append("OPENAI_API_KEY is not the placeholder")
    if other_names:
        problems.append(f"unexpected secret-like env var(s): {', '.join(other_names)}")

    if problems:
        return "FAIL", "; ".join(problems)
    return "PASS", "OPENAI_API_KEY is placeholder; no other KEY/TOKEN/SECRET vars"


def check_keys_in_files(h: ProbeHelpers) -> tuple[str, str]:
    flagged: list[str] = []
    scanned = 0
    for path, size in h.iter_scan_files():
        if path.startswith(("/proc/", "/sys/")) or path in ("/proc", "/sys"):
            continue
        if scanned >= MAX_SCAN_FILES:
            break
        scanned += 1
        if os.path.basename(path) == ".env":
            flagged.append(path)
            continue
        if size > MAX_FILE_BYTES:
            continue
        data = h.read_bytes(path, MAX_FILE_BYTES)
        if not data:
            continue
        if MODEL_KEY_MARKER in data or SK_TOKEN_RE.search(data):
            flagged.append(path)

    if flagged:
        return "FAIL", f"secret file/pattern in {', '.join(flagged)}"
    return "PASS", f"scanned {scanned} file(s); no .env or key material found"


def check_writable(h: ProbeHelpers) -> tuple[str, str]:
    tmp_writable = h.try_write("/tmp")
    tmp_info = f"/tmp {'writable' if tmp_writable else 'read-only'} (INFO)"
    protected = ("/agent", "/munix", "/", "/etc")
    writable = [d for d in protected if h.try_write(d)]
    if writable:
        return "FAIL", f"writable protected dir(s): {', '.join(writable)}; {tmp_info}"
    return "PASS", f"/agent, /munix, /, /etc read-only; {tmp_info}"


def check_docker_socket(h: ProbeHelpers) -> tuple[str, str]:
    sockets = ("/var/run/docker.sock", "/run/docker.sock")
    found = [s for s in sockets if h.path_exists(s)]
    if found:
        return "FAIL", f"docker socket present: {', '.join(found)}"
    return "PASS", "no docker socket in /var/run or /run"


def check_processes(h: ProbeHelpers) -> tuple[str, str]:
    entries = h.list_dir("/proc")
    pids = [e for e in entries if e.isdigit()]
    exposed: list[str] = []
    for pid in pids:
        raw = h.read_bytes(f"/proc/{pid}/cmdline", 65536)
        if not raw:
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
        if "munix run" in cmdline or "cargo" in cmdline:
            exposed.append(pid)

    info = f"{len(pids)} numeric pid(s) in /proc (INFO)"
    if exposed:
        return "FAIL", f"{info}; host process visible in pid(s): {', '.join(exposed)}"
    return "PASS", f"{info}; no host munix/cargo process visible"


CHECKS: tuple[tuple[str, Callable[[ProbeHelpers], tuple[str, str]]], ...] = (
    ("internet_tcp", check_internet_tcp),
    ("dns", check_dns),
    ("host_services", check_host_services),
    ("relay_scope", check_relay_scope),
    ("keys_in_env", check_keys_in_env),
    ("keys_in_files", check_keys_in_files),
    ("writable", check_writable),
    ("docker_socket", check_docker_socket),
    ("processes", check_processes),
)


def run_probe(helpers: ProbeHelpers | None = None, err=None) -> int:
    h = helpers if helpers is not None else ProbeHelpers()
    out = err if err is not None else sys.stderr
    passed = 0
    failed = 0
    for name, fn in CHECKS:
        status, detail = fn(h)
        if status == "PASS":
            passed += 1
        elif status == "FAIL":
            failed += 1
        print(f"PROBE {status} {name}: {detail}", file=out)
    print(f"PROBE SUMMARY: {passed} pass, {failed} fail", file=out)
    return 0


def main() -> int:
    return run_probe()


if __name__ == "__main__":
    sys.exit(main())
