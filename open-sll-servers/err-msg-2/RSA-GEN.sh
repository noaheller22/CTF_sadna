# Generate 2048-bit RSA private key
/usr/local/openssl-1.0.2g/bin/openssl genrsa -out server.key 2048

# Generate self-signed certificate
/usr/local/openssl-1.0.2g/bin/openssl req -x509 -new -key server.key -out server.cert -days 365 -subj "/CN=localhost"