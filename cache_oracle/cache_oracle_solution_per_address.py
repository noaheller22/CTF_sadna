import time
import math
import random
import requests

from itertools import chain
from requests import Session


SERVER = "http://127.0.0.1:5005"
NUM_CANDIDATES = 200
ADDRESS_SIZE_BYTES = 8
EVICTION_SUPERSET_SIZE_FACTOR = 20
CACHE_HIT_TIME = 0.0001

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


def read(addrs: list[int], session: Session | None = None):
  url = f"{SERVER}/read"
  json = {"addrs": addrs}

  r = session.post(url, json=json) if session else requests.post(url, json=json)
  return r.json()


def write(addrs: list[int], session: Session | None = None):
  url = f"{SERVER}/write"
  json = {"addrs": addrs}

  if session:
    session.post(url, json=json)
  else:
    requests.post(url, json=json)


def flush(session: Session | None = None):
  url = f"{SERVER}/flush"

  if session:
    session.post(url)
  else:
    requests.post(url)


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


def measure_eviction_attempt(address: int, session: Session, eviction_set_candidate: set[int], cache_config: CacheConfig) -> float:
  write([address], session)
  write(list(eviction_set_candidate), session)

  start = time.perf_counter()
  read([address], session)

  return time.perf_counter() - start


def create_address_eviction_superset(address: int, session: Session, cache_config: CacheConfig) -> set[int]:
  superset_size = cache_config.associativity * EVICTION_SUPERSET_SIZE_FACTOR
  allowed_range = list(
    chain(
      range(0, cache_config.function_address, cache_config.line_length),
      range(cache_config.function_address + cache_config.function_size, cache_config.dram_size, cache_config.line_length),
    )
  )

  count = 0
  
  superset_candidate = set(random.sample(allowed_range, superset_size))
  while measure_eviction_attempt(address, session, superset_candidate, cache_config) < TIME_THRESHOLD:
    superset_candidate = set(random.sample(allowed_range, superset_size))
    time.sleep(0.005)
  
  print("created superset")
  return superset_candidate


def build_function_eviction_set(cache_config: CacheConfig) -> list[int]:
  session = Session()

  addresses = range(cache_config.function_address, cache_config.function_address + cache_config.function_size, cache_config.line_length)
  function_eviction_set = set()
  
  for address in addresses:
    function_eviction_set.update(build_address_eviction_set(address, session, cache_config))
  
  return function_eviction_set


def build_address_eviction_set(address: int, session: Session, cache_config: CacheConfig) -> list[int]:
  eviction_set = create_address_eviction_superset(address, session, cache_config)
  minimal_eviction_set_size = cache_config.associativity
  partitions = minimal_eviction_set_size + 1
  
  eviction_set_size = len(eviction_set)
  while len(eviction_set) > minimal_eviction_set_size:
    eviction_list = list(eviction_set)
    random.shuffle(eviction_list)

    chunk_size = int(eviction_set_size / partitions)
    subsets = [set(eviction_list[i * chunk_size:(i + 1) * chunk_size]) for i in range(minimal_eviction_set_size)]
    subsets.append(set(eviction_list[minimal_eviction_set_size * chunk_size:]))
    
    for subset in subsets:
      eviction_set.difference_update(subset)
      if measure_eviction_attempt(address, session, eviction_set, cache_config) > TIME_THRESHOLD:
        break
      eviction_set.update(subset)
    
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
