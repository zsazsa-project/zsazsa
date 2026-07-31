"""Minimal Redis wire-protocol (RESP) helpers over a plain socket.

Just enough to send a command and read one reply, so the app can talk to Redis
without depending on redis-py. Shared by misp_session (reading MISP's PHP
session) and scraper_queue (publishing to the misp-scraper channel).
"""


class RedisError(Exception):
    """Raised on a Redis protocol error (e.g. failed AUTH) or a closed socket."""


def send_command(sock, *args) -> None:
    parts = [f"*{len(args)}\r\n".encode()]
    for arg in args:
        if not isinstance(arg, bytes):
            arg = str(arg).encode()
        parts.append(b"$%d\r\n%s\r\n" % (len(arg), arg))
    sock.sendall(b"".join(parts))


def _read_line(sock) -> bytes:
    buf = b""
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise RedisError("connection closed by Redis")
        buf += chunk
    return buf[:-2]


def read_reply(sock):
    """Read one reply. Handles simple strings, errors, integers, bulk strings
    and arrays (HGETALL and friends return one)."""
    line = _read_line(sock)
    kind, rest = line[:1], line[1:]
    if kind == b"+":
        return rest
    if kind == b"-":
        raise RedisError(rest.decode("utf-8", "replace"))
    if kind == b":":
        return int(rest)
    if kind == b"*":
        count = int(rest)
        if count == -1:
            return None
        return [read_reply(sock) for _ in range(count)]
    if kind == b"$":
        length = int(rest)
        if length == -1:
            return None
        data = b""
        while len(data) < length + 2:
            chunk = sock.recv(length + 2 - len(data))
            if not chunk:
                raise RedisError("connection closed by Redis mid-reply")
            data += chunk
        return data[:-2]
    raise RedisError(f"unexpected Redis reply: {line!r}")
