#!/bin/bash
set -e

# Output files
PRIV_KEY="private_1024.pem"
PUB_KEY="public_1024.pem"
CERT_FILE="server.crt"

echo "[*] Cleaning old keys..."
rm -f $PRIV_KEY $PUB_KEY $CERT_FILE

echo "[*] Generating 1024-bit RSA private key..."
openssl genrsa -out $PRIV_KEY 1024

echo "[*] Extracting public key..."
openssl rsa -in $PRIV_KEY -pubout -out $PUB_KEY

echo "[*] Generating self-signed certificate..."
openssl req -new -x509 -key $PRIV_KEY -out $CERT_FILE -days 365 \
    -subj "/CN=ErrorOracle"

echo "[+] Keys and certificate ready:"
ls -l $PRIV_KEY $PUB_KEY $CERT_FILE
