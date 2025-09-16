import argparse
import time
import random
import requests

from itertools import chain
from requests import Session


SERVER = "http://nova.cs.tau.ac.il:5005"
NUM_CANDIDATES = 200
ADDRESS_SIZE_BYTES = 8
EVICTION_SUPERSET_SIZE_FACTOR = 20
CACHE_HIT_TIME = 0.0001

TIME_THRESHOLD = CACHE_HIT_TIME * 30

class CacheConfig:
  def __init__(self, cache_config: dict[str, int]):
    self.associativity = cache_config["associativity"]
    self.function_address = cache_config["function_pointer"]
    self.function_size = cache_config["function_size"]
    self.line_length = cache_config["line"]
    self.sets_number = cache_config["sets"]
    self.dram_size = cache_config["dram_size"]
    self.function_lines = self.function_size // self.line_length


def read(addrs: list[int], user_id: str, session: Session | None = None):
  url = f"{SERVER}/read/{user_id}"
  json = {"addrs": addrs}

  r = session.post(url, json=json) if session else requests.post(url, json=json)
  return r.json()


def write(addrs: list[int], user_id: str, session: Session | None = None):
  url = f"{SERVER}/write/{user_id}"
  json = {"addrs": addrs}

  if session:
    session.post(url, json=json)
  else:
    requests.post(url, json=json)


def flush(user_id: str, session: Session | None = None):
  url = f"{SERVER}/flush/{user_id}"

  if session:
    session.post(url)
  else:
    requests.post(url)


def measure_access_function(cache_config: CacheConfig, user_id: str) -> float:
  response_json = read(
    [
      addr for addr in range(
        cache_config.function_address, cache_config.function_address + cache_config.function_size, cache_config.line_length
      )
    ],
    user_id,
  )
  execution_time = float(response_json["Time"])

  return execution_time / (cache_config.function_size // cache_config.line_length)


def measure_eviction_attempt(address: int, session: Session, eviction_set_candidate: set[int], cache_config: CacheConfig, user_id: str) -> float:
  write([address], user_id, session)
  write(list(eviction_set_candidate), user_id, session)

  response_json = read([address], user_id, session)
  
  return float(response_json["Time"])


def create_address_eviction_superset(address: int, session: Session, cache_config: CacheConfig, user_id: str) -> set[int]:
  superset_size = cache_config.associativity * EVICTION_SUPERSET_SIZE_FACTOR
  allowed_range = list(
    chain(
      range(0, cache_config.function_address, cache_config.line_length),
      range(cache_config.function_address + cache_config.function_size, cache_config.dram_size, cache_config.line_length),
    )
  )

  count = 0
  
  superset_candidate = set(random.sample(allowed_range, superset_size))
  while measure_eviction_attempt(address, session, superset_candidate, cache_config, user_id) < TIME_THRESHOLD:
    superset_candidate = set(random.sample(allowed_range, superset_size))
    time.sleep(0.005)
  
  print("created superset")
  return superset_candidate


def build_function_eviction_set(cache_config: CacheConfig, user_id: str) -> list[int]:
  session = Session()

  addresses = range(cache_config.function_address, cache_config.function_address + cache_config.function_size, cache_config.line_length)
  function_eviction_set = set()
  
  for address in addresses:
    function_eviction_set.update(build_address_eviction_set(address, session, cache_config, user_id))
  
  return function_eviction_set


def build_address_eviction_set(address: int, session: Session, cache_config: CacheConfig, user_id: str) -> list[int]:
  eviction_set = create_address_eviction_superset(address, session, cache_config, user_id)
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
      if measure_eviction_attempt(address, session, eviction_set, cache_config, user_id) > TIME_THRESHOLD:
        break
      eviction_set.update(subset)
    
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
