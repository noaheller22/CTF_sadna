#!/usr/bin/env python3
"""
Skeleton Oracle
---------------
Starter version for players:
- Connects to vulnerable SSLv2 server.
- Sends ciphertext typed as hex.
- Shows raw server response.
- No classification.
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

def send_cipher(ciphertext: bytes):
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as s:
        s.sendall(build_client_hello())
        cert = s.recv(4096)
        print(f"[*] Received server certificate ({len(cert)} bytes)")

        s.sendall(build_client_master_key(ciphertext))
        try:
            resp = s.recv(4096)
            print(f"[*] Server raw response length={len(resp)} data={resp[:32]}")
        except socket.error:
            print("[*] Connection closed by server")

if __name__ == "__main__":
    hex_ct = input("Enter ciphertext as hex: ").strip()
    try:
        ct = binascii.unhexlify(hex_ct)
    except binascii.Error:
        print("Invalid hex input")
        exit(1)
    send_cipher(ct)
