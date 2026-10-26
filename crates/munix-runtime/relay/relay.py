#!/usr/bin/env python3
"""A tiny TCP relay: relay.py <listen_port> <target_host> <target_port>

Listens on 0.0.0.0 and forwards every connection to the target, both ways, one thread pair per connection.
Standard library only. It never logs or inspects payloads.
"""
import socket
import sys
import threading

CONNECT_TIMEOUT = 10
BUFFER = 65536


def pump(src, dst):
    """Copy bytes from src to dst until src closes, then half-close dst."""
    try:
        while True:
            data = src.recv(BUFFER)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, target):
    upstream = None
    try:
        upstream = socket.create_connection(target, timeout=CONNECT_TIMEOUT)
        upstream.settimeout(None)
        client.settimeout(None)
        back = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        back.start()
        pump(client, upstream)
        back.join()
    except OSError:
        pass
    finally:
        for s in (client, upstream):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: relay.py <listen_port> <target_host> <target_port>\n")
        return 2
    try:
        listen_port = int(argv[1])
        target = (argv[2], int(argv[3]))
    except ValueError:
        sys.stderr.write("ports must be integers\n")
        return 2
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(64)
    try:
        while True:
            client, _ = server.accept()
            threading.Thread(target=handle, args=(client, target), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
