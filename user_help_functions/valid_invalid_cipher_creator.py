
######################################
### Valid/Invalid ciphers creator ####
######################################

import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

PUBLIC_KEY_PATH = "" # put a path to your public key

print("creates an invalid cipher")
ciphertext = b"\x00" * 128
invalid_ciphertext_to_send = base64.b64encode(ciphertext).decode()

print(invalid_ciphertext_to_send)

print("creates a valid cipher")
with open(PUBLIC_KEY_PATH, "rb") as f:
    pub_key = RSA.import_key(f.read()).publickey()

cipher = PKCS1_v1_5.new(pub_key)
msg = b"valid cipher"
ciphertext = cipher.encrypt(msg)
valid_ciphertext_to_send = base64.b64encode(ciphertext).decode()

print(valid_ciphertext_to_send)