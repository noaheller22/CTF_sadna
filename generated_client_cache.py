import requests
import time
import random
from collections import defaultdict

SERVER = "http://127.0.0.1:5000"
NUM_CANDIDATES = 200  # must be >> associativity
REFERENCE_ADDR = 0xdeadbeef  # fixed address for probing

# Get cache config
cfg = requests.get(f"{SERVER}/config").json()
ASSOC = cfg["associativity"]
NUM_SETS = cfg["num_sets"]
LINE_SIZE = cfg["line_size"]

def measure(addr):
    r = requests.get(f"{SERVER}/read", params={"addr": addr})
    return r.json()["time"]

def write(addr):
    requests.post(f"{SERVER}/write", json={"addr": addr})

def flush():
    requests.post(f"{SERVER}/flush")

def generate_aligned_addrs(n):
    base = 0x100000
    return [base + i * LINE_SIZE for i in range(n)]

def build_eviction_set(target_addr, candidates, threshold=0.001):
    eviction_set = []
    for c in candidates:
        flush()
        write(c)
        for a in eviction_set:
            write(a)
        t1 = measure(target_addr)
        write(c)  # add candidate to eviction set
        for a in eviction_set:
            write(a)
        t2 = measure(target_addr)
        if t2 - t1 > threshold:
            eviction_set.append(c)
        if len(eviction_set) >= ASSOC:
            break
    return eviction_set

def main():
    candidates = generate_aligned_addrs(NUM_CANDIDATES)
    flush()

    # Group candidates by cache set
    sets = defaultdict(list)
    for addr in candidates:
        set_idx = (addr // LINE_SIZE) % NUM_SETS
        sets[set_idx].append(addr)

    found_sets = []
    for set_idx, group in sets.items():
        if len(group) < ASSOC * 2:
            continue
        ref = group[0]
        others = group[1:]
        eviction_set = build_eviction_set(ref, others)
        if len(eviction_set) == ASSOC:
            print(f"Found eviction set for set {set_idx}:")
            print(eviction_set)
            found_sets.append((set_idx, eviction_set))

    print(f"\nTotal eviction sets found: {len(found_sets)}")

if __name__ == "__main__":
    main()
