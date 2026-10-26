#!/usr/bin/env python3
"""Munix shim: keeps the agent container's stdio as Munix's MCP channel.

    munix_shim.py serve -- <agent command...>   PID 1 of the agent container
    munix_shim.py connect                       the agent's MCP server command

The container's stdin and stdout are the MCP channel to Munix. The agent is an ordinary program that expects to
start its MCP server as a subprocess, so `serve` starts the agent with stdin from /dev/null and its stdout sent to
stderr (its prints can never reach the channel), listens on a Unix socket, and pumps bytes between the one
connection it accepts and its own stdin/stdout. `connect` is that subprocess: it pumps its own stdin/stdout to the
socket. Neither side looks at the bytes, and nothing is logged about them.

Python 3 standard library only.
"""

import os
import signal
import socket
import subprocess
import sys
import threading
import time

DEFAULT_SOCKET = "/tmp/munix-mcp.sock"
CONNECT_WAIT_SECONDS = 5.0
CHUNK = 65536
# After the channel closes, how long the agent may keep running before it is terminated, then killed.
CLOSE_GRACE_SECONDS = 5.0
KILL_GRACE_SECONDS = 5.0
# After the agent exits, how long to wait for the last bytes of the channel to be written out.
DRAIN_SECONDS = 1.0


def socket_path():
    return os.environ.get("MUNIX_SHIM_SOCKET") or DEFAULT_SOCKET


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def exit_code(status):
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def pump_fd_to_socket(sock):
    """Copies this process's stdin to the socket; at end of input, half-closes the socket."""
    try:
        while True:
            data = os.read(0, CHUNK)
            if not data:
                break
            sock.sendall(data)
    except OSError:
        pass
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def pump_socket_to_fd(sock, done):
    """Copies the socket to this process's stdout until the socket ends."""
    try:
        while True:
            data = sock.recv(CHUNK)
            if not data:
                break
            write_all(1, data)
    except OSError:
        pass
    done.set()


# connect ------------------------------------------------------------------------------------------------------


def run_connect():
    path = socket_path()
    deadline = time.monotonic() + CONNECT_WAIT_SECONDS
    sock = None
    while sock is None:
        candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            candidate.connect(path)
            sock = candidate
        except OSError:
            candidate.close()
            if time.monotonic() >= deadline:
                sys.stderr.write("munix-shim: could not reach the Munix channel\n")
                return 1
            time.sleep(0.05)
    done = threading.Event()
    threading.Thread(target=pump_fd_to_socket, args=(sock,), daemon=True).start()
    threading.Thread(target=pump_socket_to_fd, args=(sock, done), daemon=True).start()
    done.wait()
    return 0


# serve --------------------------------------------------------------------------------------------------------


class Serve:
    def __init__(self, command):
        self.command = command
        self.agent_pid = None
        self.agent_status = None
        self.signalled_at = None
        self.closed_at = None
        self.killed = False

    def forward(self, signum, _frame):
        if self.agent_pid is not None and self.agent_status is None:
            try:
                os.kill(self.agent_pid, signum)
            except OSError:
                pass
        if self.signalled_at is None:
            self.signalled_at = time.monotonic()

    def reap(self):
        """Reaps every exited child (this process may be PID 1, so orphans land here)."""
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            if pid == self.agent_pid:
                self.agent_status = status

    def escalate(self):
        """Terminates, then kills, an agent that has outlived the channel or a signal it was sent."""
        if self.agent_status is not None:
            return
        now = time.monotonic()
        if self.closed_at is not None and self.signalled_at is None and now - self.closed_at >= CLOSE_GRACE_SECONDS:
            self.forward(signal.SIGTERM, None)
        if self.signalled_at is not None and not self.killed and now - self.signalled_at >= KILL_GRACE_SECONDS:
            self.killed = True
            try:
                os.kill(self.agent_pid, signal.SIGKILL)
            except OSError:
                pass

    def run(self):
        path = socket_path()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            listener.bind(path)
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
        listener.listen(1)
        listener.settimeout(0.05)

        signal.signal(signal.SIGTERM, self.forward)
        signal.signal(signal.SIGINT, self.forward)

        try:
            agent = subprocess.Popen(
                self.command,
                stdin=subprocess.DEVNULL,
                stdout=2,
                stderr=None,
            )
        except OSError:
            sys.stderr.write("munix-shim: could not start the agent command\n")
            return 127
        self.agent_pid = agent.pid

        conn = None
        while conn is None and self.agent_status is None:
            self.reap()
            if self.agent_status is not None:
                break
            try:
                conn, _ = listener.accept()
            except (socket.timeout, BlockingIOError):
                self.escalate()
            except OSError:
                time.sleep(0.05)

        # Exactly one connection: stop listening, so nothing else can connect.
        listener.close()
        try:
            os.unlink(path)
        except OSError:
            pass

        if conn is None:
            return exit_code(self.agent_status)

        conn.settimeout(None)
        to_agent_done = threading.Event()
        from_agent_done = threading.Event()
        threading.Thread(target=self._stdin_to_conn, args=(conn, to_agent_done), daemon=True).start()
        threading.Thread(target=pump_socket_to_fd, args=(conn, from_agent_done), daemon=True).start()

        while self.agent_status is None:
            time.sleep(0.05)
            self.reap()
            if self.closed_at is None and (to_agent_done.is_set() or from_agent_done.is_set()):
                self.closed_at = time.monotonic()
            if from_agent_done.is_set():
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self.escalate()

        # The agent is gone: give the last bytes of the channel a moment to go out, then finish.
        from_agent_done.wait(DRAIN_SECONDS)
        try:
            conn.close()
        except OSError:
            pass
        return exit_code(self.agent_status)

    @staticmethod
    def _stdin_to_conn(conn, done):
        pump_fd_to_socket(conn)
        done.set()


def usage():
    sys.stderr.write("usage: munix_shim.py serve -- <agent command...> | munix_shim.py connect\n")
    return 2


def main(argv):
    if len(argv) >= 2 and argv[1] == "connect" and len(argv) == 2:
        return run_connect()
    if len(argv) >= 4 and argv[1] == "serve" and argv[2] == "--":
        return Serve(argv[3:]).run()
    return usage()


if __name__ == "__main__":
    code = main(sys.argv)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
    os._exit(code)
