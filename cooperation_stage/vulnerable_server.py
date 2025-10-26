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

# Load your private key
with open("cooperation_stage/private4.pem", "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

lockout = {
    "global": 0    
}
curr_cipher = {}
LOCK_DURATION = 30

# Decryption & Padding Check
def is_padding_valid(ciphertext: bytes):
    cipher = PKCS1_v1_5.new(private_key)
    try :
        result = cipher.decrypt(ciphertext, None)
        is_valid = result != b''
        print("is valid is ", is_valid)
        return is_valid
    except Exception:
        print("Exception")
        return None

@app.route("/send_cipher/<player_id>", methods=["POST"])
def send_cipher(player_id):
    if player_id not in lockout :
        lockout[player_id] = 0
        curr_cipher[player_id] = None
    ciphertext = request.data # raw bytes
    now = time.time()
    if now < lockout["global"] or now < lockout[player_id] :
        return f"Server busy, please try again later\n"
    else : 
        result = is_padding_valid(ciphertext)
        if result is True:
            # Valid padding: block everything
            lockout["global"] = now + LOCK_DURATION
            lockout[player_id] = now + LOCK_DURATION
        elif result is None :
            return "Couldn't parse message. Please try again.\n"
        else:
            # Invalid padding: block this port only
            lockout[player_id] = now + LOCK_DURATION
        curr_cipher[player_id] = ciphertext
        return f"Got message. Starting to process\n"

@app.route("/check_status/<player_id>", methods=["GET"])
def check_status(player_id):
    now = time.time()
    if (player_id not in lockout) or (curr_cipher[player_id] == None) :
        return f"No message sent\n" 
    elif now < lockout[player_id] :
        return f"Processing...\n"
    else :
        return f"Done with cipher: { base64.b64encode(curr_cipher[player_id]).decode()}\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    app.run(host="0.0.0.0", port=5004)