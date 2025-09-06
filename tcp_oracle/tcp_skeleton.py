import socket
import sys

HOST = ""   # Oracle server address as it been given to you
PORT = ???     # Oracle server port as it been given to you

def send_cipher(cipher_bytes):
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as s:
            s.sendall(cipher_bytes)
    except Exception as e:
        print(f"[!] Client error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <cipher_hex>")
        sys.exit(1)

    cipher_ascii = sys.argv[1]
    cipher_bytes = cipher_ascii.encode("ascii")

    send_cipher(cipher_bytes)