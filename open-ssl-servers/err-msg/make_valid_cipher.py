from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import os

# Load the server's public key
with open("public_1024.pem", "rb") as f:
    pubkey = RSA.importKey(f.read())

cipher = PKCS1_v1_5.new(pubkey)

# Construct a 48-byte premaster secret:
# starts with version (0x03 0x00) + 46 random bytes
premaster = b"\x03\x00" + os.urandom(46)

# Encrypt under PKCS#1 v1.5 (adds 00 02 || PS || 00)
ciphertext = cipher.encrypt(premaster)

with open("valid_cipher.bin", "wb") as f:
    f.write(ciphertext)

print("Wrote valid_cipher.bin with premaster starting 0x0300")
