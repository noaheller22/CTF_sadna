import socket
import struct
from contextlib import suppress


class ErrorOracle:
    def __init__(self, host: str = "127.0.0.1", port: int = 4444):
        self._addr = (host, port)
        self._sock: socket.socket | None = None

    # ---------- one-shot helper (stateless) ----------
    def query(self, ct: bytes) -> bool:
        pkt = struct.pack("!H", len(ct)) + ct
        with socket.create_connection(self._addr) as s:
            s.sendall(pkt)
            reply = s.recv(256)          # "OK\n" or error string
        return reply.startswith(b"OK")

    # ---------- optional streaming helpers ----------
    def send(self, ct: bytes) -> None:
        if self._sock is None:
            self._sock = socket.create_connection(self._addr)
        pkt = struct.pack("!H", len(ct)) + ct
        self._sock.sendall(pkt)

    def recv(self, bufsize: int = 4096) -> bytes:
        if self._sock is None:
            raise RuntimeError("send() first, then recv()")
        return self._sock.recv(bufsize)

    def close(self) -> None:
        with suppress(Exception):
            if self._sock:
                self._sock.close()
        self._sock = None