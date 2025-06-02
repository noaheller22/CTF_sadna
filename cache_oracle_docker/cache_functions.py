import random
import time
from collections import defaultdict


class CacheLine:
  def __init__(self, lines_amount: int):
    self._lines_amount = lines_amount
    self.cache_lines: list[int] = []
  
  def append(self, address: int) -> None:
    if len(self.cache_lines) >= self._lines_amount:
      self.cache_lines.pop(0)
        
    self.cache_lines.append(address) 


class Cache:
  # Cache Config
  CACHE_LINE_SIZE = 64
  CACHE_ASSOCIATIVITY = 4
  CACHE_NUM_SETS = 16
  CACHE_SIZE = CACHE_LINE_SIZE * CACHE_ASSOCIATIVITY * CACHE_NUM_SETS

  # Timing Config
  DRAM_TO_CACHE_TIME = 50
  CACHE_HIT_TIME = 0.0001
  CACHE_MISS_TIME = CACHE_HIT_TIME * DRAM_TO_CACHE_TIME

  # Function Config
  FUNCTION_SIZE = 16
  FUNCTION_POINTER = random.randint(0, CACHE_SIZE - FUNCTION_SIZE - 1)

  def __init__(self):
    self.cache: dict[int, CacheLine] = defaultdict(CacheLine(self.CACHE_ASSOCIATIVITY))

  def get_cache_configuration(self) -> dict[str, int]:
      return {"line": self.CACHE_LINE_SIZE, "sets": self.CACHE_NUM_SETS, "associativity": self.CACHE_ASSOCIATIVITY}

  def _get_cache_address(self, dram_address: int) -> int:
      return (dram_address // self.CACHE_LINE_SIZE) % self.CACHE_NUM_SETS
  
  def _get_cache_lines(self, dram_address) -> CacheLine:
      cache_address = self._get_cache_address(dram_address)
      return self.cache[cache_address]

  def reset_cache(self) -> None:
      self.cache = defaultdict(CacheLine(self.CACHE_ASSOCIATIVITY))

  def cache_changing_function(self) -> None:
      for dram_address in range(self.FUNCTION_POINTER, self.FUNCTION_POINTER + self.FUNCTION_SIZE):
          cache_lines = self._get_cache_lines(dram_address)
          cache_lines.append(dram_address)

  def prime(self, dram_address: int) -> None:
      cache_lines = self._get_cache_lines(dram_address)
      cache_lines.append(dram_address)

  def probe(self, dram_address: int) -> None:
      cache_lines = self._get_cache_lines(dram_address).cache_lines

      if dram_address in cache_lines:
          time.sleep(self.CACHE_HIT_TIME)
      else:
          time.sleep(self.CACHE_MISS_TIME)
          cache_lines.append(dram_address)
