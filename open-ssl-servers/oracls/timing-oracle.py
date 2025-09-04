"""
timing_oracle.py
Python helper that talks to the server compiled from timing_oracle.c
(listening on TCP 4445 by default).

Typical usage
-------------
from timing_oracle import TimingOracle
oracle = TimingOracle("ctf.local", 4445)

dt_us = oracle.query(ciphertext, repeats=5)   # average RTT in micro-seconds
print("round-trip µs:", dt_us)
"""
import socket
import struct
import time


class TimingOracle:
    def __init__(self, host: str = "127.0.0.1", port: int = 4445):
        self._addr = (host, port)

    def query(self, ct: bytes, *, repeats: int = 1) -> float:
        """
        Measure round-trip time for *repeats* identical queries and
        return the **average** duration in micro-seconds.
        """
        pkt = struct.pack("!H", len(ct)) + ct
        tot_ns = 0
        for _ in range(repeats):
            t0 = time.perf_counter_ns()
            with socket.create_connection(self._addr) as s:
                s.sendall(pkt)
                _ = s.recv(3)            # always b"OK\n"
            tot_ns += time.perf_counter_ns() - t0
        return (tot_ns / repeats) / 1_000  # → µs

    # convenience single-shot alias
    __call__ = query
