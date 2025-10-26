import random
import time
from collections import defaultdict


DRAM_SIZE = 65_536


class CacheLine:
  # Timing Config
  CACHE_HIT_TIME = 0.0001
  DRAM_TO_CACHE_ACCESS_TIME_RATIO = 50
  CACHE_MISS_TIME = CACHE_HIT_TIME * DRAM_TO_CACHE_ACCESS_TIME_RATIO

  def __init__(self, lines_amount: int):
    self._lines_amount = lines_amount
    self.cache_lines: list[int] = []
  
  def append(self, address: int, should_sleep: bool = True) -> None:
    address_in_cache = address in self.cache_lines

    if address_in_cache:
      self.cache_lines.remove(address)
    self.cache_lines.append(address)

    if len(self.cache_lines) > self._lines_amount:
      self.cache_lines.pop(0)

    if should_sleep:
      time.sleep(self.CACHE_HIT_TIME if address_in_cache else self.CACHE_MISS_TIME)


class Cache:
  # Cache Config
  CACHE_LINE_SIZE = 64
  CACHE_ASSOCIATIVITY = 4
  CACHE_NUM_SETS = 64
  CACHE_SIZE = CACHE_LINE_SIZE * CACHE_ASSOCIATIVITY * CACHE_NUM_SETS

  # Function Config
  FUNCTION_SIZE = 1024
  FUNCTION_POINTER = random.randint(0, CACHE_SIZE - FUNCTION_SIZE - 1)

  def __init__(self):
    self._cache: dict[int, CacheLine] = defaultdict(self._create_cache_line)
  
  def _create_cache_line(self) -> CacheLine:
    return CacheLine(self.CACHE_ASSOCIATIVITY)

  def get_cache_configuration(self) -> dict[str, int]:
    return {
      "associativity": self.CACHE_ASSOCIATIVITY,
      "function_pointer": self.FUNCTION_POINTER,
      "function_size": self.FUNCTION_SIZE,
      "line": self.CACHE_LINE_SIZE,
      "dram_size": DRAM_SIZE,
    }
  
  def _get_line_address(self, dram_address: int) -> int:
    return dram_address // self.CACHE_LINE_SIZE

  def _get_cache_address(self, dram_address: int) -> int:
    return (self._get_line_address(dram_address)) % self.CACHE_NUM_SETS
  
  def _get_cache_lines(self, dram_address) -> CacheLine:
    cache_address = self._get_cache_address(dram_address)
    return self._cache[cache_address]

  def reset_cache(self) -> None:
    self._cache = defaultdict(self._create_cache_line)

  def cache_changing_function(self) -> None:
    for dram_address in range(self.FUNCTION_POINTER, self.FUNCTION_POINTER + self.FUNCTION_SIZE):
      self.probe(dram_address)

  def prime(self, dram_address: int) -> None:
    cache_lines = self._get_cache_lines(dram_address)
    line_address = self._get_line_address(dram_address)
    cache_lines.append(line_address, should_sleep=False)

  def probe(self, dram_address: int) -> None:
    cache_lines = self._get_cache_lines(dram_address)
    line_address = self._get_line_address(dram_address)
    cache_lines.append(line_address)
