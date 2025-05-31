import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

##testing invalid cipher
print("Teseting invalid cipher")
ciphertext = b"\x00" * 256
b64_ciphertext = base64.b64encode(ciphertext).decode()

response = requests.post("http://localhost:5000/oracle", json={"ciphertext": b64_ciphertext})
print("Status code:", response.status_code)
print("Response JSON:", response.json())


print("Teseting valid cipher")
with open("public.pem", "rb") as f:
    pub_key = RSA.import_key(f.read())

cipher = PKCS1_v1_5.new(pub_key)
msg = b"test message"
ciphertext = cipher.encrypt(msg)
b64_ciphertext = base64.b64encode(ciphertext).decode()

response = requests.post("http://localhost:5000/oracle", json={"ciphertext": b64_ciphertext})
print("Status code:", response.status_code)
print("Response JSON:", response.json())