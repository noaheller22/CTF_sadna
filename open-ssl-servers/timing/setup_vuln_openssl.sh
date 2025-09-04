#!/bin/bash
set -e

cd "$(dirname "$0")"   # always relative to script location
BASE_DIR=$HOME
OPENSSL_DIR=$BASE_DIR/openssl-1.0.1f

echo "=== Setting up Timing Oracle (OpenSSL 1.0.1f) ==="

# 1. Download + extract OpenSSL 1.0.1f if not exists
if [ ! -d "$OPENSSL_DIR" ]; then
  echo "[*] Downloading OpenSSL 1.0.1f..."
  wget -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz -O $BASE_DIR/openssl-1.0.1f.tar.gz
  tar -xzf $BASE_DIR/openssl-1.0.1f.tar.gz -C $BASE_DIR
  cd $OPENSSL_DIR
  echo "[*] Running ./config no-asm..."
  ./config no-asm
  echo "[*] Patching Makefiles (remove -m486)..."
  find . -name Makefile -exec sed -i 's/-m486//g' {} +
  echo "[*] Building..."
  make clean
  make
else
  echo "[*] OpenSSL 1.0.1f already present in $OPENSSL_DIR"
fi

cd "$(dirname "$0")"   # back to timing folder

# 2. Generate keys if missing
if [ ! -f "private_1024.pem" ]; then
  echo "[*] Generating private key..."
  openssl genrsa -out private_1024.pem 1024
fi

if [ ! -f "server.crt" ]; then
  echo "[*] Generating self-signed certificate..."
  openssl req -new -x509 -key private_1024.pem -out server.crt -days 365 -subj "/CN=TimingOracle"
fi

echo
echo "Setup complete!"
echo "To start the vulnerable server, run:"
echo "$OPENSSL_DIR/apps/openssl s_server -accept 4434 -key $(pwd)/private_1024.pem -cert $(pwd)/server.crt"
