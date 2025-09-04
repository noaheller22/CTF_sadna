#!/usr/bin/env python3
"""
Full Oracle
-----------
Reference solution:
- Accepts ciphertext typed as hex.
- Sends to vulnerable SSLv2 server.
- Classifies result:
    [-] INVALID => padding rejected (server responds with error).
    [+] VALID   => padding accepted (server advances, no padding error).
"""

import socket, binascii

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4433
CIPHER_KIND = b"\x01\x00\x80"

def build_client_hello():
    msg_type = b"\x01"
    version = b"\x00\x02"
    cipher_specs = CIPHER_KIND
    cs_len = len(cipher_specs).to_bytes(2, "big")
    sid_len = (0).to_bytes(2, "big")
    challenge = b"X" * 16
    chall_len = len(challenge).to_bytes(2, "big")
    payload = msg_type + version + cs_len + sid_len + chall_len + cipher_specs + challenge
    header = ((0x80 | (len(payload) >> 8))).to_bytes(1, "big") + (len(payload) & 0xff).to_bytes(1, "big")
    return header + payload

def build_client_master_key(ciphertext: bytes):
    msg_type = b"\x02"
    cipher_kind = CIPHER_KIND
    clear_key_len = (0).to_bytes(2, "big")
    enc_key_len = len(ciphertext).to_bytes(2, "big")
    key_arg_len = (0).to_bytes(2, "big")
    payload = msg_type + cipher_kind + clear_key_len + enc_key_len + key_arg_len + ciphertext
    header = ((0x80 | (len(payload) >> 8))).to_bytes(1, "big") + (len(payload) & 0xff).to_bytes(1, "big")
    return header + payload

def query_oracle(ciphertext: bytes):
    try:
        with socket.create_connection((SERVER_IP, SERVER_PORT), timeout=3) as s:
            s.sendall(build_client_hello())
            _ = s.recv(4096)  # server certificate

            s.sendall(build_client_master_key(ciphertext))
            resp = s.recv(4096)

            if resp:
                # Any bytes = explicit error, padding rejected
                print("[-] INVALID: padding rejected (server error).")
            else:
                # No bytes but no crash = server advanced
                print("[+] VALID: padding accepted (handshake advanced).")
    except Exception:
        print("[-] INVALID: connection error (no result).")

if __name__ == "__main__":
    hex_ct = input("Enter ciphertext as hex: ").strip()
    try:
        ct = binascii.unhexlify(hex_ct)
    except binascii.Error:
        print("Invalid hex input")
        exit(1)
    query_oracle(ct)
