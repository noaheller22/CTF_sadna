import socket

SERVER_IP = ""   
SERVER_PORT = 4433           

def send_cipher(cipher: bytes) -> bytes:
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as s:
        s.sendall(cipher)
        reply = s.recv(4096)
    return reply

if __name__ == "__main__":
    # example usage
    test = b"A" * 256
    response = send_cipher(test)
    print("Server replied:", response)
