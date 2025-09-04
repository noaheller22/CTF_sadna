#!/bin/bash
set -e

OPENSSL_VER="0.9.8"
SRC_DIR="$HOME/CTF_sadna/open-sll-servers/err-msg"
OPENSSL_DIR="$SRC_DIR/openssl-$OPENSSL_VER"
OPENSSL_TARBALL="openssl-$OPENSSL_VER.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/old/0.9.x/$OPENSSL_TARBALL"

echo "[*] Cleaning old build..."
rm -rf "$OPENSSL_DIR" "$SRC_DIR/$OPENSSL_TARBALL"

cd "$SRC_DIR"

echo "[*] Downloading OpenSSL $OPENSSL_VER ..."
wget "$OPENSSL_URL"

echo "[*] Extracting..."
tar xzf "$OPENSSL_TARBALL"

cd "openssl-$OPENSSL_VER"

echo "[*] Configuring..."
./config --prefix="$OPENSSL_DIR" --openssldir="$OPENSSL_DIR"

echo "[*] Building libraries and tests..."
make

echo "[*] Building application binaries (s_server, s_client, openssl)..."
cd apps
make
cd ..

if [ -f apps/s_server ]; then
    echo "[+] OpenSSL $OPENSSL_VER build complete!"
    echo "---------------------------------------------------------"
    echo "Server binary: $OPENSSL_DIR/apps/s_server"
    echo "Client binary: $OPENSSL_DIR/apps/s_client"
    echo "Main openssl:  $OPENSSL_DIR/apps/openssl"
else
    echo "[!] ERROR: s_server not found, build may have failed."
    exit 1

echo "[*] Forcing rebuild of apps..."
cd apps
make clean
make
cd ..

if [ -x apps/s_server ]; then
    echo "[+] Success! Found apps/s_server"
    echo "Run it with:"
    echo "$OPENSSL_DIR/apps/s_server -accept 4433 -key private_1024.pem -cert server.crt -ssl2"
else
    echo "[!] ERROR: apps/s_server still missing."
fi
