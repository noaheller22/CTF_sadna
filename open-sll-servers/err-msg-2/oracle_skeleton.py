import socket
import ssl
import sys

def query_oracle(ciphertext, server_host="localhost", server_port=4433):
    """
    Send ciphertext to the vulnerable server and return the response.
    Args:
        ciphertext (bytes): Raw RSA ciphertext.
        server_host (str): Server hostname.
        server_port (int): Server port.
    Returns:
        str: Server response (e.g., 'valid:Valid PKCS#1 v1.5 padding' or 'invalid:<error>').
    """
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl._create_unverified_context()  # Ignore self-signed cert
        secure_sock = context.wrap_socket(sock, server_hostname=server_host)

        # Connect and send ciphertext
        secure_sock.connect((server_host, server_port))
        secure_sock.send(ciphertext)

        # Receive response (up to 1024 bytes)
        response = secure_sock.recv(1024).decode()
        secure_sock.close()

        return response

    except Exception as e:
        return f"error:Oracle error: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 oracle_skeleton.py <hex_ciphertext>")
        sys.exit(1)

    # Convert hex input to bytes
    try:
        ciphertext = bytes.fromhex(sys.argv[1])
    except ValueError:
        print("Error: Ciphertext must be hex-encoded")
        sys.exit(1)

    response = query_oracle(ciphertext)
    print(f"Server response: {response}")