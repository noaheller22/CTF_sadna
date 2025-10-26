import base64
import logging
import time
from collections import defaultdict

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from cache import Cache


PRIVATE_KEY_PATH = "private.pem"
OPEN_PORT = 5005
CUTOFF_LENGTH = 100


# Setup
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
cipher = PKCS1_v1_5.new(private_key)
app = Flask(__name__)

user_cache_mapping = defaultdict(Cache)


# Routes
@app.route("/config/<user_id>", methods=["GET"])
def config(user_id):
    global user_cache_mapping

    user_id = request.view_args["user_id"]
    cache_instance = user_cache_mapping[user_id]

    return jsonify(cache_instance.get_cache_configuration())


@app.route("/write/<user_id>", methods=["POST"])
def write(user_id):
    global user_cache_mapping
    cache_instance = user_cache_mapping[user_id]

    write_notice = "Granted"
    addrs = request.json.get("addrs", [])

    try:
        for addr in addrs:
            cache_instance.prime(int(addr))
    
    except ValueError:
        write_notice = "Errored - addresses must be an ints"
    except IndexError:
        write_notice = "Errored - addresses must be inside the DRAM"
    except Exception:
        write = "Errored"

    return jsonify({"Write": write_notice})


@app.route("/read/<user_id>", methods=["POST"])
def read(user_id):
    global user_cache_mapping
    cache_instance = user_cache_mapping[user_id]

    read_notice = "Granted"
    execution_time = None
    addrs = request.json.get("addrs", [])

    if len(addrs) > CUTOFF_LENGTH:
        return jsonify({"Read": "Errored - request contains too many addresses", "Time": 0})

    try:
        
        start = time.perf_counter()
        for addr in addrs:
            cache_instance.probe(int(addr))
        execution_time = time.perf_counter() - start
    
    except ValueError:
        read_notice = "Errored - address must be an int"
    except IndexError:
        read_notice = "Errored - address must be inside the DRAM"
    except Exception as error:
        read_notice = f"Errored: {error}"

    return jsonify({"Read": read_notice, "Time": execution_time})


@app.route("/oracle/<user_id>", methods=["POST"])
def oracle(user_id):
    global user_cache_mapping
    cache_instance = user_cache_mapping[user_id]

    try:
        data = request.get_json()
        ciphertext = data.get("ciphertext")
        if ciphertext is None:
            return jsonify(error="Missing 'ciphertext'"), 400

        b64_ciphertext = base64.b64decode(ciphertext)
        result = cipher.decrypt(b64_ciphertext, None)

        is_valid = result != b''
        
        if is_valid:
            cache_instance.cache_changing_function()

        return jsonify("request accepted")

    except Exception as e:
        return jsonify({"error": f"an error has accured: {e}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=OPEN_PORT)
