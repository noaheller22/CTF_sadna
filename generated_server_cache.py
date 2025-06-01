from flask import Flask, request, jsonify
import time
import random

app = Flask(__name__)

# Cache config
CACHE_LINE_SIZE = 64
CACHE_ASSOCIATIVITY = 4
CACHE_NUM_SETS = 16
CACHE_SIZE = CACHE_LINE_SIZE * CACHE_ASSOCIATIVITY * CACHE_NUM_SETS

# Simulated cache: maps set index to a list of addresses
cache = {i: [] for i in range(CACHE_NUM_SETS)}

# Access timing simulation
CACHE_HIT_TIME = 0.0001
CACHE_MISS_TIME = 0.005

def get_cache_set_index(addr):
    return (addr // CACHE_LINE_SIZE) % CACHE_NUM_SETS

@app.route("/read", methods=["GET"])
def read():
    addr = int(request.args.get("addr"))
    set_idx = get_cache_set_index(addr)
    is_hit = addr in cache[set_idx]

    if is_hit:
        time.sleep(CACHE_HIT_TIME)
    else:
        time.sleep(CACHE_MISS_TIME)

    return jsonify({
        "addr": addr,
        "time": CACHE_HIT_TIME if is_hit else CACHE_MISS_TIME,
        "cache_hit": is_hit
    })

@app.route("/write", methods=["POST"])
def write():
    addr = int(request.json["addr"])
    set_idx = get_cache_set_index(addr)
    lines = cache[set_idx]

    if addr in lines:
        return jsonify({"status": "already_cached"})

    if len(lines) >= CACHE_ASSOCIATIVITY:
        evicted = lines.pop(0)
    else:
        evicted = None

    lines.append(addr)
    return jsonify({"status": "cached", "evicted": evicted})

@app.route("/flush", methods=["POST"])
def flush():
    global cache
    cache = {i: [] for i in range(CACHE_NUM_SETS)}
    return jsonify({"status": "flushed"})

@app.route("/config", methods=["GET"])
def config():
    return jsonify({
        "line_size": CACHE_LINE_SIZE,
        "num_sets": CACHE_NUM_SETS,
        "associativity": CACHE_ASSOCIATIVITY
    })

if __name__ == "__main__":
    app.run(debug=True)
