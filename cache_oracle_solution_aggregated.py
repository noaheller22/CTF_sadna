import time
import math
import random

import requests
from itertools import chain


SERVER = "http://127.0.0.1:5005"
NUM_CANDIDATES = 200
ADDRESS_SIZE_BYTES = 8  # explicit and clear
EVICTION_SUPERSET_SIZE_FACTOR = 4
CACHE_HIT_TIME = 0.0001

SUPERSET_THRESHOLD = CACHE_HIT_TIME * 50
TIME_THRESHOLD = CACHE_HIT_TIME * 40


class CacheConfig:
    def __init__(self, cache_config: dict[str, int]):
        self.associativity = cache_config["associativity"]
        self.function_address = cache_config["function_pointer"]
        self.function_size = cache_config["function_size"]
        self.line_length = cache_config["line"]
        self.sets_number = cache_config["sets"]
        self.dram_size = cache_config["dram_size"]
        self.function_lines = self.function_size // self.line_length


def read(addrs: list[int]):
    r = requests.post(f"{SERVER}/read", json={"addrs": addrs})
    return r.json()


def write(addrs: list[int]):
    requests.post(f"{SERVER}/write", json={"addrs": addrs})


def flush():
    requests.post(f"{SERVER}/flush")


def measure_access_function(cache_config: CacheConfig) -> float:
    start = time.perf_counter()
    read(
        [
            addr for addr in range(
                cache_config.function_address, cache_config.function_address + cache_config.function_size, cache_config.line_length
            )
        ]
    )
    return (time.perf_counter() - start) / (cache_config.function_size // cache_config.line_length)


def measure_eviction_attempt(eviction_set_candidate: set[int], cache_config: CacheConfig) -> float:
    write(list(range(cache_config.function_address, cache_config.function_address + cache_config.function_size)))
    write(list(eviction_set_candidate))
    return measure_access_function(cache_config)


def create_eviction_superset(cache_config: CacheConfig) -> set[int]:
    superset_size = cache_config.function_lines * cache_config.associativity * EVICTION_SUPERSET_SIZE_FACTOR
    allowed_range = list(
        chain(
            range(0, cache_config.function_address, cache_config.line_length),
            range(cache_config.function_address + cache_config.function_size, cache_config.dram_size, cache_config.line_length),
        )
    )

    superset_candidate = set(random.sample(allowed_range, superset_size))
    while measure_eviction_attempt(superset_candidate, cache_config) < SUPERSET_THRESHOLD:
       print("set is not evicting, looking for another candidate")
       superset_candidate = set(random.sample(allowed_range, superset_size))
    
    print("created superset")
    return superset_candidate


def build_function_eviction_set(cache_config: CacheConfig) -> list[int]:
    eviction_set = create_eviction_superset(cache_config)
    minimal_eviction_set_size = cache_config.associativity * cache_config.function_lines
    partitions = minimal_eviction_set_size + 1
    
    eviction_set_size = len(eviction_set)
    while len(eviction_set) > minimal_eviction_set_size:
        max_time = 0
        max_subset = set()
        print("candidate size", len(eviction_set))
        eviction_list = list(eviction_set)
        random.shuffle(eviction_list)

        chunk_size = int(eviction_set_size / partitions)
        subsets = [set(eviction_list[i * chunk_size:(i + 1) * chunk_size]) for i in range(minimal_eviction_set_size)]
        subsets.append(set(eviction_list[minimal_eviction_set_size * chunk_size:]))
        
        for subset in subsets:
            eviction_set.difference_update(subset)
            eviction_time = measure_eviction_attempt(eviction_set, cache_config)

            if eviction_time > max_time:
                max_subset = subset
                max_time = eviction_time

            eviction_set.update(subset)
        
        eviction_set.difference_update(max_subset)
        eviction_set_size = len(eviction_set)
    
    print("found minimal eviction set")
    return eviction_set


def bleichenbacher_oracle(ciphertext: bytes, eviction_set: set[int], cache_config: CacheConfig, use_flush: bool = False) -> bool:
    write(list(range(cache_config.function_address, cache_config.function_address + cache_config.function_size))) 

    if use_flush:
        flush()
    else:
        write(list(eviction_set))

    r = requests.post(f"{SERVER}/oracle", json={"ciphertext": ciphertext})
    if r.status_code != 200:
        print(r.json())
        raise ValueError
    
    average_reload_time = measure_access_function(cache_config)

    return average_reload_time < TIME_THRESHOLD


def main():
    cyphertexts = [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "zlFQJpaemhCmuONXmJ+JmsxdUv328UV/N3EQnFIlzy0OaYbagg/NIdKd8yClGQ8KYGE/kwynV6G+cAYR4Dfz+CUfHDooq2laQkS87rDtKvwsxNq/kOO3UqhsjtLgKrQTrfqIQMujbVlfAroZFsIUXCiaoHxNV8Uoiu2TXxnDk5k=",
    ]
    cache_config = CacheConfig(requests.get(f"{SERVER}/config").json())
    eviction_set = build_function_eviction_set(cache_config)

    responses = [bleichenbacher_oracle(cyphertext, eviction_set, cache_config) for cyphertext in cyphertexts]
    print(responses)


if __name__ == "__main__":
    main()
