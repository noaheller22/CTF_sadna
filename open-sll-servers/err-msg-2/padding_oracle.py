import socket
import ssl
import sys

def query_oracle(ciphertext, server_host="localhost", server_port=4433):
    """
    Send ciphertext to the vulnerable server and determine padding validity.
    Args:
        ciphertext (bytes): Raw RSA ciphertext.
        server_host (str): Server hostname.
        server_port (int): Server port.
    Returns:
        bool: True if padding is valid, False otherwise.
    """
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl._create_unverified_context()
        secure_sock = context.wrap_socket(sock, server_hostname=server_host)

        # Connect and send ciphertext
        secure_sock.connect((server_host, server_port))
        secure_sock.send(ciphertext)

        # Receive response (up to 1024 bytes)
        response = secure_sock.recv(1024).decode()
        secure_sock.close()

        # Parse response
        if response.startswith("valid:"):
            print(f"Valid padding for ciphertext: {ciphertext.hex()[:20]}...")
            return True
        else:
            print(f"Invalid padding for ciphertext: {ciphertext.hex()[:20]}... Error: {response}")
            return False

    except Exception as e:
        print(f"Oracle error: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 padding_oracle.py <hex_ciphertext>")
        sys.exit(1)

    # Convert hex input to bytes
    try:
        ciphertext = bytes.fromhex(sys.argv[1])
    except ValueError:
        print("Error: Ciphertext must be hex-encoded")
        sys.exit(1)

    is_valid = query_oracle(ciphertext)
    print(f"Padding is {'valid' if is_valid else 'invalid'}")