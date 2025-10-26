import argparse
import time
import random

import requests
from itertools import chain


SERVER = "http://nova.cs.tau.ac.il:5005"
NUM_CANDIDATES = 200
ADDRESS_SIZE_BYTES = 8
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


def read(addrs: list[int], user_id: str):
    r = requests.post(f"{SERVER}/read/{user_id}", json={"addrs": addrs})
    return r.json()


def write(addrs: list[int], user_id: str):
    requests.post(f"{SERVER}/write/{user_id}", json={"addrs": addrs})


def flush(user_id: str):
    requests.post(f"{SERVER}/flush{user_id}")


def measure_access_function(cache_config: CacheConfig, user_id: str) -> float:
    start = time.perf_counter()
    read(
        [
            addr for addr in range(
                cache_config.function_address, cache_config.function_address + cache_config.function_size, cache_config.line_length
            )
        ],
        user_id,
    )
    return (time.perf_counter() - start) / (cache_config.function_size // cache_config.line_length)


def measure_eviction_attempt(eviction_set_candidate: set[int], cache_config: CacheConfig, user_id: str) -> float:
    write(list(range(cache_config.function_address, cache_config.function_address + cache_config.function_size)), user_id)
    write(list(eviction_set_candidate), user_id)
    return measure_access_function(cache_config, user_id)


def create_eviction_superset(cache_config: CacheConfig, user_id: str) -> set[int]:
    superset_size = cache_config.function_lines * cache_config.associativity * EVICTION_SUPERSET_SIZE_FACTOR
    allowed_range = list(
        chain(
            range(0, cache_config.function_address, cache_config.line_length),
            range(cache_config.function_address + cache_config.function_size, cache_config.dram_size, cache_config.line_length),
        )
    )

    superset_candidate = set(random.sample(allowed_range, superset_size))
    while measure_eviction_attempt(superset_candidate, cache_config, user_id) < SUPERSET_THRESHOLD:
       print("set is not evicting, looking for another candidate")
       superset_candidate = set(random.sample(allowed_range, superset_size))
    
    print("created superset")
    return superset_candidate


def build_function_eviction_set(cache_config: CacheConfig, user_id: str) -> list[int]:
    eviction_set = create_eviction_superset(cache_config, user_id)
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
            eviction_time = measure_eviction_attempt(eviction_set, cache_config, user_id)

            if eviction_time > max_time:
                max_subset = subset
                max_time = eviction_time

            eviction_set.update(subset)
        
        eviction_set.difference_update(max_subset)
        eviction_set_size = len(eviction_set)
    
    print("found minimal eviction set")
    return eviction_set


def bleichenbacher_oracle(ciphertext: bytes, eviction_set: set[int], cache_config: CacheConfig, user_id: str, use_flush: bool = False) -> bool:
    write(list(range(cache_config.function_address, cache_config.function_address + cache_config.function_size)), user_id) 

    if use_flush:
        flush(user_id)
    else:
        write(list(eviction_set), user_id)

    r = requests.post(f"{SERVER}/oracle/{user_id}", json={"ciphertext": ciphertext})
    if r.status_code != 200:
        print(r.json())
        raise ValueError
    
    average_reload_time = measure_access_function(cache_config, user_id)

    return average_reload_time < TIME_THRESHOLD


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cipher_candidate")
    parser.add_argument("--user_id")
    args = parser.parse_args()

    ciphertext = args.cipher_candidate
    user_id = args.user_id

    cache_config = CacheConfig(requests.get(f"{SERVER}/config/{user_id}").json())
    eviction_set = build_function_eviction_set(cache_config, user_id)

    responses = bleichenbacher_oracle(ciphertext, eviction_set, cache_config, user_id)
    print(responses)


if __name__ == "__main__":
    main()
