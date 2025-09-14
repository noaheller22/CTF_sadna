import base64
import logging

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from cache import Cache


PRIVATE_KEY_PATH = "private.pem"
OPEN_PORT = 5005


# Setup
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
cipher = PKCS1_v1_5.new(private_key)
cache_instance = Cache()
app = Flask(__name__)


# Routes
@app.route("/config", methods=["GET"])
def config():
    global cache_instance
    return jsonify(cache_instance.get_cache_configuration())


@app.route("/flush", methods=["POST"])
def flush():
    global cache_instance
    flush_notice = "Success"
    
    try:
        cache_instance.reset_cache()
    except Exception:
        flush_notice = "Errored"

    return jsonify({"Flush": flush_notice})


@app.route("/write", methods=["POST"])
def write():
    global cache_instance
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


@app.route("/read", methods=["POST"])
def read():
    global cache_instance
    read_notice = "Granted"

    addrs = request.json.get("addrs", [])

    try:
        for addr in addrs:
            cache_instance.probe(int(addr))
    
    except ValueError:
        read_notice = "Errored - address must be an int"
    except IndexError:
        read_notice = "Errored - address must be inside the DRAM"
    except Exception:
        read_notice = "Errored"
        
    return jsonify({"Read": read_notice})


@app.route("/oracle", methods=["POST"])
def oracle():
    global cache_instance
    
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
