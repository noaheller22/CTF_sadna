from flask import Flask, request, abort
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import argparse
import os
from Crypto.PublicKey import RSA
import base64
from Crypto.Cipher import PKCS1_v1_5

app = Flask(__name__)

# 🔐 Load your private key (replace this with your actual key)
with open("cooperation_stage/private3.pem", "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

# 🔁 Lockout states (timestamp until unlocked)
lockout = {
    "endpoint_1": 0,
    "endpoint_2": 0,
    "global": 0
}

curr_cipher = {
    "endpoint_1": None,
    "endpoint_2": None,    
}

# ⏱ Duration to lock (in seconds)
LOCK_DURATION = 10

"""# 🛑 Middleware to enforce lockouts
@app.before_request
def check_lockout():
    now = time.time()
    port = int(request.environ.get('SERVER_PORT'))

    if now < lockout["global"]:
        abort(403, "Global lockout in effect.")
    if now < lockout[port]:
        abort(403, f"Port {port} is temporarily locked.")"""

# 🔐 Decryption & Padding Check
def is_padding_valid(ciphertext: bytes):
    cipher = PKCS1_v1_5.new(private_key)
    try :
        result = cipher.decrypt(ciphertext, None)
        is_valid = result != b''
        return is_valid
    except Exception:
        print("Exception")
        return False
    """try:
        private_key.decrypt(ciphertext, padding.PKCS1v15())
        return True
    except Exception:
        return False"""

# 📬 Endpoint to send the cipher
@app.route("/send_cipher_1", methods=["POST"])
def send_cipher_1():
    print("got cipher 1")
    ciphertext = request.data # raw bytes
    print(f"cipher text is {base64.b64encode(ciphertext).decode()}")
    now = time.time()
    curr_cipher['endpoint_1'] = ciphertext

    if now < lockout["global"] or now < lockout['endpoint_1'] :
        print(f"Server busy, please try again later\n")
        return f"Server busy, please try again later\n"
    else : 
        if is_padding_valid(ciphertext):
            # Valid padding: block everything
            print("Cipher is valid!")
            lockout["global"] = now + LOCK_DURATION
        else:
            # Invalid padding: block this port only
            lockout['endpoint_1'] = now + LOCK_DURATION
        print(f"Got message. Starting to process\n")
        return f"Got message. Starting to process\n"

@app.route("/send_cipher_2", methods=["POST"])
def send_cipher_2():
    print("got cipher 2")
    ciphertext = request.data # raw bytes
    now = time.time()
    curr_cipher['endpoint_2'] = ciphertext

    if now < lockout["global"] or now < lockout['endpoint_2'] :
        return f"Server busy, please try again later\n"
    else : 
        if is_padding_valid(ciphertext):
            # Valid padding: block everything
            lockout["global"] = now + LOCK_DURATION
        else:
            # Invalid padding: block this port only
            lockout['endpoint_2'] = now + LOCK_DURATION
        print(f"Got message. Starting to process...\n")
        return f"Got message. Starting to process...\n"

# ✅ Ping endpoint_1
@app.route("/check_status_1", methods=["GET"])
def check_status_1():
    if curr_cipher['endpoint_1'] == None :
        print(f"No message sent\n" )
        return f"No message sent\n" 
    elif now < lockout['endpoint_1'] :
        print(f"Processing...\n")
        return f"Processing...\n"
    else :
        print(f"Done with cyper: {curr_cipher['endpoint_1']}\n")
        return f"Done with cyper: {curr_cipher['endpoint_1']}\n"

# ✅ Ping endpoint_2
@app.route("/check_status_2", methods=["GET"])
def check_status_2():
    if curr_cipher['endpoint_2'] == None :
        print(f"No message sent\n")
        return f"No message sent\n" 
    elif now < lockout['endpoint_2'] :
        print(f"Processing...\n")
        return f"Processing...\n"
    else :
        print(f"Done with cyper: {curr_cipher['endpoint_2']}\n")
        return f"Done with cyper: {curr_cipher['endpoint_2']}\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    app.run(host="0.0.0.0", port=5005)