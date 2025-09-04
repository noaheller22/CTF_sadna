import socket, time, binascii

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4434

def classify(cipher_hex: str) -> str:
    """Send ciphertext once and classify by response time"""
    ciphertext = binascii.unhexlify(cipher_hex.strip())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((SERVER_HOST, SERVER_PORT))
    start = time.perf_counter()
    s.sendall(ciphertext)
    _ = s.recv(4096)  # ignore "done"
    elapsed = time.perf_counter() - start
    s.close()

    # Threshold chosen between "fast" (~invalid) and "slow" (~valid)
    if elapsed > 0.05:   # 30 ms threshold works (gap is 50 ms)
        return "valid"
    else:
        return "invalid"

if __name__ == "__main__":
    valid_hex   = open("valid_hex.txt").read()
    invalid_hex = open("invalid_hex.txt").read()

    print("Valid ciphertext classified as:", classify(valid_hex))
    print("Invalid ciphertext classified as:", classify(invalid_hex))
