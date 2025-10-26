import multiprocessing
import base64

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from concurrent.futures import ThreadPoolExecutor


NUM_CORES = multiprocessing.cpu_count()  # Determine number of CPU cores for parallelization


with open("private.pem", "rb") as key_file:  # Load private key
    private_key = RSA.import_key(key_file.read())


cipher = PKCS1_v1_5.new(private_key)  # Setup cipher

app = Flask(__name__)


def decrypt_ciphertext(ct_bytes):
    """
    Returns True if the ciphertext has valid PKCS#1 v1.5 padding, False otherwise.
    """
    try:
        return cipher.decrypt(ct_bytes, None) != b''
    except Exception:
        return False


@app.route("/oracle", methods=["POST"])
def oracle():
    try:
        data = request.get_json()
        # Batch mode: list of ciphertexts
        if "ciphertexts" in data:
            b64_ciphertexts = data["ciphertexts"]
            if not isinstance(b64_ciphertexts, list):
                return jsonify({"error": "'ciphertexts' must be a list"}), 400

            # Decode all ciphertexts
            ciphertexts = [base64.b64decode(c) for c in b64_ciphertexts]

             # Parallel decryption
            with ThreadPoolExecutor(max_workers=NUM_CORES) as executor:
                results = list(executor.map(decrypt_ciphertext, ciphertexts))

            return jsonify({"valid_list": results})

        # Single ciphertext mode
        elif "ciphertext" in data:
            b64_ciphertext = data["ciphertext"]
            ciphertext = base64.b64decode(b64_ciphertext)
            result = cipher.decrypt(ciphertext, None)
            is_valid = result != b''
            return jsonify({"valid": is_valid})

        else:
            return jsonify({"error": "Missing 'ciphertext' or 'ciphertexts'"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5006, threaded=True)
