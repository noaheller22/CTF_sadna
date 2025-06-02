import time
import requests


SERVER = "http://127.0.0.1:5000"
NUM_CANDIDATES = 200
ADDRESS_SIZE_BYTES = 8  # explicit and clear
TIME_THRESHOLD = 0.0001 * 30


def probe(addr):
    r = requests.get(f"{SERVER}/read", params={"addr": addr})
    return r.json()["time"]


def prime(addr):
    requests.post(f"{SERVER}/write", json={"addr": addr})


def flush():
    requests.post(f"{SERVER}/flush")


def generate_aligned_addresses(amount: int, alignment: int) -> list[int]:
    base = 0x100000
    return [base + i * alignment for i in range(amount)]


def measure_time(addr: int) -> float:
    start = time.perf_counter()
    requests.get(f"{SERVER}/read", params={"addr": addr})
    return time.perf_counter() - start


def build_eviction_function_set(target_address: int, candidates: list[int], cache_associativity: int, threshold: float = 0.001):
    eviction_set = []

    for candidate in candidates:
        flush()
        prime(candidate)
        for evictor in eviction_set:
            prime(evictor)
        t1 = measure_time(target_address)

        prime(candidate)
        for evictor in eviction_set:
            prime(evictor)
        t2 = measure_time(target_address)

        if t2 - t1 > threshold:
            eviction_set.append(candidate)

        if len(eviction_set) >= cache_associativity:
            break

    return eviction_set


def bleichenbacher_oracle(ciphertext: bytes, eviction_set: list[int]) -> bool:
    for addr in eviction_set:
        prime(addr)

    r = requests.post(f"{SERVER}/oracle", json={"ciphertext": ciphertext.hex()})
    assert r.status_code == 200

    probe_time = 0
    for addr in eviction_set:
        probe_time += measure_time(addr)
    
    avg_time = probe_time / len(eviction_set)

    return avg_time > TIME_THRESHOLD


def main():
    cyphertexts = []
    cache_config = requests.get(f"{SERVER}/config").json()
    function_info = requests.get(f"{SERVER}/function").json()

    cache_associativity = cache_config["associativity"]
    cache_sets_number = cache_config["num_sets"]
    line_size = cache_config["line_size"]
    function_pointer = function_info["function_pointer"]

    candidates = generate_aligned_addresses(200, line_size)
    target_set = (function_pointer // line_size) % cache_sets_number
    same_set_candidates = [address for address in candidates if (address // line_size) % cache_sets_number == target_set]
    eviction_set = build_eviction_function_set(function_pointer, same_set_candidates, cache_associativity)

    responses = [bleichenbacher_oracle(cyphertext, eviction_set) for cyphertext in cyphertexts]
