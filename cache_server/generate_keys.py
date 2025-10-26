from Crypto.PublicKey import RSA

# Generate a 2048-bit RSA key pair
key = RSA.generate(2048)

# Export private key
with open("private.pem", "wb") as priv_file:
    priv_file.write(key.export_key())

# Export public key
with open("public.pem", "wb") as pub_file:
    pub_file.write(key.publickey().export_key())

print("Keys generated and saved as 'private.pem' and 'public.pem'")
