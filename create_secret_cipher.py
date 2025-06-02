import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

with open("public.pem", "rb") as f:
    pub_key = RSA.import_key(f.read())

cipher = PKCS1_v1_5.new(pub_key)
msg = b"the secret flag!! whoa whoa"
ciphertext = cipher.encrypt(msg)

with open("secret_cipher.bin", "wb") as f:
    f.write(ciphertext)

print("secret cipher using pub_key at 'public.pem' saved at 'secret_cipher.bin'")