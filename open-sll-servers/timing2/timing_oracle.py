import socket, time, binascii, statistics

SERVER_HOST = "127.0.0.1"   # change if server runs elsewhere
SERVER_PORT = 4434

def query(cipher_hex: str, trials: int = 5):
    """Send ciphertext (hex string), measure average response time"""
    ciphertext = binascii.unhexlify(cipher_hex.strip())
    times = []
    results = []
    for _ in range(trials):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        start = time.perf_counter()
        s.sendall(ciphertext)
        data = s.recv(4096)
        elapsed = time.perf_counter() - start
        s.close()
        times.append(elapsed)
        results.append(data.decode(errors="ignore").strip())
    return statistics.mean(times), results

if __name__ == "__main__":
    # Example usage: test with two ciphertexts
    valid_hex   = open("valid_hex.txt").read()
    invalid_hex = open("invalid_hex.txt").read()

    avg_time_valid, res_valid = query(valid_hex, trials=10)
    avg_time_invalid, res_invalid = query(invalid_hex, trials=10)

    print("[*] Valid ciphertext results:", res_valid)
    print("[*] Avg time (valid):", avg_time_valid)

    print("[*] Invalid ciphertext results:", res_invalid)
    print("[*] Avg time (invalid):", avg_time_invalid)
