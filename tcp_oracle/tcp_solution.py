import socket
import sys

HOST = "127.0.0.1"   # Oracle server address
PORT = 9000          # Oracle server port

def send_cipher(cipher_bytes):
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as s:
            s.sendall(cipher_bytes)
            try:
                data = s.recv(1024)
                if data == b"":
                    print("[+] Connection closed gracefully (valid padding)")
                else:
                    print("[?] Got some data:", data)
            except ConnectionResetError:
                print("[-] Connection reset by peer (invalid padding)")
    except Exception as e:
        print(f"[!] Client error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <cipher_hex>")
        sys.exit(1)

    cipher_ascii = sys.argv[1]
    cipher_bytes = cipher_ascii.encode("ascii")

    send_cipher(cipher_bytes)
