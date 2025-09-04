#!/bin/bash
echo "[*] Starting vulnerable OpenSSL 0.9.8 server on port 4433 ..."
./openssl-0.9.8/apps/openssl s_server -accept 4433 -key private_1024.pem -cert server.crt -ssl2