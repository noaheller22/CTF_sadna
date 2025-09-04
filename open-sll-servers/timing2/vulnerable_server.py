import socket, subprocess, os

OPENSSL_BIN = "/a/home/cc/students/cs/danielknebel/CTF_sadna/open-sll-servers/timing2/openssl-0.9.8/bin/openssl"
PRIVATE_KEY = "/a/home/cc/students/cs/danielknebel/CTF_sadna/open-sll-servers/timing2/openssl-0.9.8zg/server.key"
CERT_FILE   = "/a/home/cc/students/cs/danielknebel/CTF_sadna/open-sll-servers/timing2/openssl-0.9.8zg/server.crt"


def handle_client(client_sock):
    ciphertext = client_sock.recv(2048)
    if not ciphertext:
        client_sock.send(b"error:No ciphertext")
        return

    with open("ciphertext.bin", "wb") as f:
        f.write(ciphertext)

    result = subprocess.run([
        OPENSSL_BIN, "rsautl", "-decrypt", "-in", "ciphertext.bin",
        "-inkey", PRIVATE_KEY, "-pkcs"
    ], capture_output=True)

    os.remove("ciphertext.bin")

    # Important: don’t leak stderr → attacker must use timing
    if result.returncode == 0:
        client_sock.send(b"valid")
    else:
        client_sock.send(b"invalid")

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 4434))
    server_sock.listen(5)
    print("Timing-vulnerable server listening on port 4434")
    while True:
        client_sock, _ = server_sock.accept()
        handle_client(client_sock)
        client_sock.close()

if __name__ == "__main__":
    main()
