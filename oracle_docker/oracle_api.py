from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

# Load private key
with open("private.pem", "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

# Setup cipher
cipher = PKCS1_v1_5.new(private_key)

app = Flask(__name__)

@app.route("/oracle", methods=["POST"])
def oracle():
    try:
        data = request.get_json()
        b64_ciphertext = data.get("ciphertext")
        if b64_ciphertext is None:
            return jsonify({"error": "Missing 'ciphertext'"}), 400

        ciphertext = base64.b64decode(b64_ciphertext)
        result = cipher.decrypt(ciphertext, None)

        is_valid = result != b''

        return jsonify({"valid": is_valid})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
