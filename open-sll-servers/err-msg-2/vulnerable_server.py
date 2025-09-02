import socket
import ssl
import subprocess
import os

# Paths
OPENSSL_BIN = "/a/home/cc/students/cs/danielknebel/openssl-1.0.2g/bin/openssl"
PRIVATE_KEY = "/a/home/cc/students/cs/danielknebel/CTF_sadna/open-sll-servers/err-msg-2/openssl-1.0.2g/server.key"
CERT_FILE = "/a/home/cc/students/cs/danielknebel/CTF_sadna/open-sll-servers/err-msg-2/openssl-1.0.2g/server.cert"

def handle_client(client_sock):
    try:
        # Receive ciphertext (up to 2048 bytes for 2048-bit RSA)
        ciphertext = client_sock.recv(2048)
        if not ciphertext:
            client_sock.send(b"error:No ciphertext received")
            return

        # Write ciphertext to temporary file
        with open("ciphertext.bin", "wb") as f:
            f.write(ciphertext)

        # Decrypt with OpenSSL, enforcing PKCS#1 v1.5 padding
        result = subprocess.run([
            OPENSSL_BIN, "rsautl", "-decrypt", "-in", "ciphertext.bin",
            "-inkey", PRIVATE_KEY, "-pkcs"
        ], capture_output=True, text=True)

        # Clean up
        os.remove("ciphertext.bin")

        # Send response
        if result.returncode == 0:
            # Valid padding
            client_sock.send(b"valid:Valid PKCS#1 v1.5 padding")
        else:
            # Invalid padding, send OpenSSL error
            error_msg = result.stderr.strip() or "Unknown padding error"
            client_sock.send(f"invalid:{error_msg}".encode())

    except Exception as e:
        client_sock.send(f"error:Server error: {str(e)}".encode())

def main():
    # Verify paths
    for path in [OPENSSL_BIN, CERT_FILE, PRIVATE_KEY]:
        if not os.path.exists(path):
            print(f"Error: Missing file {path}")
            return

    # Create TCP socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(('0.0.0.0', 4433))
    except Exception as e:
        print(f"Error binding to port 4433: {e}")
        return
    server_sock.listen(5)

    # Wrap with TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=PRIVATE_KEY)
    print("Starting vulnerable server on port 4433")

    while True:
        try:
            client_sock, addr = server_sock.accept()
            secure_sock = context.wrap_socket(client_sock, server_side=True)
            handle_client(secure_sock)
            secure_sock.close()
        except Exception as e:
            print(f"Server error: {e}")

if __name__ == "__main__":
    main()