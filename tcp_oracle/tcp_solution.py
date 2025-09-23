import argparse
import socket


HOST = "132.67.247.151"   # Oracle server address
PORT = 5003          # Oracle server port


def send_cipher(cipher_bytes):
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as s:
            s.sendall(cipher_bytes)
            try:
                data = s.recv(1024)
                if data == b"":
                    print("[+] Connection closed gracefully (valid padding, or problem with the cipher like incorrect length)")
                else:
                    print("[?] Got some data:", data)
            except ConnectionResetError:
                print("[-] Connection reset by peer (invalid padding)")
    except Exception as e:
        print(f"[!] Client error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cipher_candidate")
    args = parser.parse_args()

    ciphertext = args.cipher_candidate

    cipher_bytes = ciphertext.encode("ascii")

    send_cipher(cipher_bytes)
