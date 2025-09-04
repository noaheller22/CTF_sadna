# oracle.py - robust one-shot oracle for your server
import socket
import struct
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]

class ErrorOracle:
    def __init__(self, host: str = "127.0.0.1", port: int = 4444, timeout: float = 3.0):
        self.addr = (host, port)
        self.timeout = timeout

    def _exchange(self, ct: BytesLike) -> bytes:
        if not isinstance(ct, (bytes, bytearray, memoryview)):
            raise TypeError("ciphertext must be bytes-like")
        n = len(ct)
        if not (0 <= n <= 0xFFFF):
            raise ValueError("ciphertext length must fit in 2 bytes (0..65535)")
        pkt = struct.pack("!H", n) + bytes(ct)
        with socket.create_connection(self.addr, timeout=self.timeout) as s:
            s.sendall(pkt)
            # we won't send more; let server know
            with suppress(OSError):
                s.shutdown(socket.SHUT_WR)
            # read until EOF to avoid truncation
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks)

    def query_text(self, ct: BytesLike) -> str:
        """Return server reply as text ('OK\\n' or OpenSSL error text)."""
        return self._exchange(ct).decode("utf-8", errors="replace")

    def is_valid(self, ct: BytesLike) -> bool:
        """True iff server replied exactly 'OK' (ignoring newline/space)."""
        return self._exchange(ct).strip() == b"OK"


# Optional quick check
if __name__ == "__main__":
    from contextlib import suppress
    oracle = ErrorOracle()
    bogus = b"\x00" * 16
    print("Reply:", oracle.query_text(bogus))
    print("Valid?", oracle.is_valid(bogus))
