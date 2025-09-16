"""
error_oracle.py
Python helper that talks to the server compiled from err_oracle.c
(listening on TCP 4444 by default).

Usage
-----
from error_oracle import ErrorOracle
oracle = ErrorOracle("ctf.local", 4444)

if oracle.query(ciphertext):
    print("padding is VALID")
else:
    print("padding is BAD")

# If you need raw access:
oracle.send(ciphertext)        # writes and keeps the socket open
response = oracle.recv()       # reads the full server reply
oracle.close()                 # tidy-up
"""
import socket
import struct
from contextlib import suppress


class ErrorOracle:
    def __init__(self, host: str = "127.0.0.1", port: int = 4444):
        self._addr = (host, port)
        self._sock: socket.socket | None = None

    # ---------- one-shot helper (most users will call only this) ----------
    def query(self, ct: bytes) -> bool:
        """
        Return True if the server replied “OK”, False otherwise.
        Opens and closes a fresh connection each call (stateless).
        """
        pkt = struct.pack("!H", len(ct)) + ct
        with socket.create_connection(self._addr) as s:
            s.sendall(pkt)
            reply = s.recv(256)          # "OK\n"  or "bad decrypt\n"
        return reply.startswith(b"OK")

    # ---------- raw stream helpers (optional) ----------
    def send(self, ct: bytes) -> None:
        """
        Send *only* the length-prefixed ciphertext and keep the connection
        open so the caller may decide when to recv() later.
        """
        if self._sock is not None:       # reuse the same socket if still open
            sock = self._sock
        else:
            sock = self._sock = socket.create_connection(self._addr)
        pkt = struct.pack("!H", len(ct)) + ct
        sock.sendall(pkt)

    def recv(self, bufsize: int = 4096) -> bytes:
        """
        Receive up to *bufsize* bytes from the still-open socket.
        Raises RuntimeError if send() has not been called first.
        """
        if self._sock is None:
            raise RuntimeError("No open socket – call send() first")
        return self._sock.recv(bufsize)

    def close(self) -> None:
        with suppress(Exception):
            if self._sock:
                self._sock.close()
        self._sock = None
