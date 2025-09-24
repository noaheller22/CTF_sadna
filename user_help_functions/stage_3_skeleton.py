import argparse
import socket


def send_cipher(host: str, port: int, cipher_bytes: bytes):
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.sendall(cipher_bytes)
    except Exception as e:
        print(f"[!] Client error: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cipher_candidate")
    parser.add_argument("--host")
    parser.add_argument("--port")
    args = parser.parse_args()

    ciphertext = args.cipher_candidate
    host = args.host
    port = int(args.port)

    cipher_bytes = ciphertext.encode("ascii")

    send_cipher(host, port, cipher_bytes)


if __name__ == "__main__":
    main()
