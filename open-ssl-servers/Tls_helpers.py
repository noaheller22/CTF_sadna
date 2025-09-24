#!/usr/bin/env python3
import struct
import hmac
from hashlib import md5, sha1
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TLS_VERSION = b"\x03\x01"
CIPHER_SUITE = b"\x00\x2f"
BLOCK_SIZE = 16
SEQUENCE_NUMBER = 3

# ---------------- Session Keys ----------------
class Keys:
    def __init__(self, key_block: bytes):
        self.client_mac_key = key_block[:20]
        self.server_mac_key = key_block[20:40]
        self.client_write_key = key_block[40:56]
        self.server_write_key = key_block[56:72]
        self.client_initialization_vector = key_block[72:88]
        self.server_initialization_vector = key_block[88:104]


# ---------------- PRF ----------------
def p_hash(hash_mod, secret: bytes, seed: bytes, size: int):
    result = b""
    A = seed
    while len(result) < size:
        A = hmac.new(secret, A, hash_mod).digest()
        result += hmac.new(secret, A + seed, hash_mod).digest()
    return result[:size]

def tls_prf(secret: bytes, label: bytes, seed: bytes, size: int) -> bytes:
    half = (len(secret) + 1) // 2
    s1, s2 = secret[:half], secret[-half:]
    md5_bytes = p_hash(md5, s1, label + seed, size)
    sha1_bytes = p_hash(sha1, s2, label + seed, size)
    return bytes(x ^ y for x, y in zip(md5_bytes, sha1_bytes))

# ---------------- TLS record helpers ----------------
def recv_tls_record(conn):
    header = conn.recv(5)
    if not header:
        return None, None
    ctype = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return ctype, body

def build_server_hello(server_random: bytes) -> bytes:
    session_id = b"\x00"
    comp_methods = b"\x01\x00"
    body = (b"\x02" +
            struct.pack(">I", 38 + 1 + 2 + 1)[1:] +
            TLS_VERSION + server_random + session_id + CIPHER_SUITE + comp_methods)
    return b"\x16" + TLS_VERSION + struct.pack(">H", len(body)) + body

def build_certificate(cert_bytes: bytes) -> bytes:
    cert_list = struct.pack(">I", len(cert_bytes))[1:] + cert_bytes
    all_certs = struct.pack(">I", len(cert_list))[1:] + cert_list
    body = b"\x0b" + struct.pack(">I", len(all_certs))[1:] + all_certs
    return b"\x16" + TLS_VERSION + struct.pack(">H", len(body)) + body

def build_server_hello_done() -> bytes:
    body = b"\x0e\x00\x00\x00"
    return b"\x16" + TLS_VERSION + struct.pack(">H", len(body)) + body

def build_alert(description: int) -> bytes:
    level = 2  # fatal
    payload = bytes([level, description])
    return b"\x15" + TLS_VERSION + struct.pack(">H", len(payload)) + payload


# ---------------- Main TLS logic ----------------
def handle_client(conn, priv_key, cert_bytes):
    try:
        # ---- ClientHello ----
        ctype, body = recv_tls_record(conn)
        if ctype != 0x16 or body[0] != 0x01:
            return
        print("[*] Got ClientHello")
        client_random = body[6:38]

        # ---- Send ServerHello, Certificate, ServerHelloDone ----
        server_random = urandom(32)
        conn.sendall(build_server_hello(server_random))
        conn.sendall(build_certificate(cert_bytes))
        conn.sendall(build_server_hello_done())
        print("[*] Sent ServerHello, Certificate, ServerHelloDone")

        # ---- ClientKeyExchange ----
        ctype, body = recv_tls_record(conn)
        if ctype != 0x16 or body[0] != 0x10:
            return

        enc_len = struct.unpack(">H", body[4:6])[0]
        encrypted = body[6:6+enc_len]

        try:
            premaster = priv_key.decrypt(encrypted, padding.PKCS1v15())
        except Exception:
            # Padding invalid → short path
            print("[-] Decryption failed (padding invalid)")
            conn.sendall(build_alert(20))  # Always send bad_record_mac
            return
        print("[+] Decrypted premaster")

        # ---- ChangeCipherSpec ----
        ctype, body = recv_tls_record(conn)
        if ctype != 0x14:
            conn.sendall(build_alert(20))
            return

        # ---- Finished ----
        ctype, body = recv_tls_record(conn)
        if ctype != 0x16:
            conn.sendall(build_alert(20))
            return
        encrypted_finished = body

        # ---- Derive keys ----
        master_secret = tls_prf(premaster, b"master secret", client_random+server_random, 48)
        key_block = tls_prf(master_secret, b"key expansion", server_random+client_random, 104)
        client_mac = key_block[:20]
        client_key = key_block[40:56]
        client_iv = key_block[72:88]

        # ---- Decrypt Finished ----
        cipher = Cipher(algorithms.AES(client_key), modes.CBC(client_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_finished) + decryptor.finalize()

        # Remove padding
        pad_len = plaintext[-1] + 1
        hs_sig_plus_mac = plaintext[:-pad_len]

        verify_mac = hs_sig_plus_mac[-20:]
        hs_sig = hs_sig_plus_mac[:-20]

        mac_input = (SEQUENCE_NUMBER.to_bytes(8, "big") +
                     bytes([0x16]) + TLS_VERSION +
                     len(hs_sig).to_bytes(2, "big") + hs_sig)
        mac = hmac.new(client_mac, mac_input, sha1).digest()

        if mac != verify_mac:
            print("[-] MAC check failed")
            conn.sendall(build_alert(20))  # Same alert as padding error
            return

        print("[+] Valid MAC, handshake complete")
        conn.sendall(b"OK\n")

    finally:
        conn.close()

