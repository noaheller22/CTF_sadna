import base64
import socket

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


HOST = "0.0.0.0"
PORT = 5003
PRIVATE_KEY_PATH = "private_tcp.pem"


# Load private key
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

# Setup cipher
cipher = PKCS1_v1_5.new(private_key)


def handle_client(conn, addr, private_key):
    try:
        data = conn.recv(4096)
        if not data:
            conn.close()
            return

        ciphertext = base64.b64decode(data)
        result = cipher.decrypt(ciphertext, None)
        is_valid = result != b''
        if is_valid: # If decryption succeeds -> valid padding -> graceful close
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            print(f"[+] Valid padding from {addr}")
        else: # Invalid padding -> send TCP RST
            # SO_LINGER with zero timeout makes close() -> RST
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
            print(f"[-] Invalid padding from {addr}")

    except Exception as e:
        print(f"[!] Error with client {addr}: {e}")
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Oracle listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, private_key)


if __name__ == "__main__":
    import struct
    main()
