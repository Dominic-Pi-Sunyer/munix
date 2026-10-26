"""Minimal threaded SMTP server that records messages (smtpd is gone in Python 3.12)."""

import socketserver
import threading


class _Handler(socketserver.StreamRequestHandler):
    def reply(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())
        self.wfile.flush()

    def handle(self) -> None:
        self.reply("220 fake ESMTP")
        mail_from, rcpts = "", []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode(errors="replace").rstrip("\r\n")
            cmd = line.upper()
            if cmd.startswith(("EHLO", "HELO")):
                self.reply("250 fake")
            elif cmd.startswith("MAIL FROM:"):
                mail_from, rcpts = line[10:].strip(), []
                self.reply("250 OK")
            elif cmd.startswith("RCPT TO:"):
                rcpts.append(line[8:].strip().strip("<>"))
                self.reply("250 OK")
            elif cmd == "DATA":
                self.reply("354 go")
                data = []
                while True:
                    row = self.rfile.readline().decode(errors="replace")
                    if row in (".\r\n", ".\n", ""):
                        break
                    data.append(row[1:] if row.startswith("..") else row)
                self.server.messages.append(
                    {"from": mail_from.strip("<>"), "rcpts": rcpts, "data": "".join(data)}
                )
                self.reply("250 OK queued")
            elif cmd == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("250 OK")


class FakeSmtp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.messages: list[dict] = []
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.server_address[1]}"

    def start(self) -> "FakeSmtp":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
