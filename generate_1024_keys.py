from Crypto.PublicKey import RSA

# Generate a 1024-bit RSA key pair
key = RSA.generate(1024)

# Export private key
with open("private_1024.pem", "wb") as priv_file:
    priv_file.write(key.export_key())

# Export public key
with open("public_1024.pem", "wb") as pub_file:
    pub_file.write(key.publickey().export_key())

print("1024-bit RSA key pair generated!")
