import base64

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from cache_functions import Cache


# Setup
with open("private.pem", "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

cipher = PKCS1_v1_5.new(private_key)
cache_instance = Cache()
app = Flask(__name__)


# Routes
@app.route("/config", methods=["GET"])
def config():
    global cache_instance
    return jsonify(cache_instance.get_cache_configuration())


@app.route("/flash", methods=["POST"])
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

    try:
       cache_instance.prime(int(request.args.get("addr")))
    
    except ValueError:
        write_notice = "Errored - address must be an int"
    except IndexError:
        write_notice = "Errored - address must be inside the DRAM"
    except Exception:
        write = "Errored"

    return jsonify({"Write": write_notice})


@app.route("/read", methods=["GET"])
def read():
    global cache_instance
    read_notice = "Granted"

    try:
        cache_instance.probe(int(request.args.get("addr")))
    
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
        b64_ciphertext = data.get("ciphertext")
        if b64_ciphertext is None:
            return jsonify({"error": "Missing 'ciphertext'"}), 400

        ciphertext = base64.b64decode(b64_ciphertext)
        result = cipher.decrypt(ciphertext, None)

        is_valid = result != b''
        
        if is_valid:
            cache_instance.cache_changing_function()

        return jsonify({"request accepted"})

    except Exception as e:
        return jsonify({"error": "an error has accured"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3244)
