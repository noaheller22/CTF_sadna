# Use a slightly newer Debian base image
FROM debian:8

# Install build tools
RUN apt-get update && apt-get install -y build-essential wget perl

WORKDIR /root

# Copy in RSA key and certificate from your repo
COPY private_1024.pem /root/server.key
COPY server.crt /root/server.crt

# Download and build OpenSSL 1.0.1f (vulnerable to timing oracle CVE-2016-2107)
RUN wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz && \
    tar xzf openssl-1.0.1f.tar.gz && \
    cd openssl-1.0.1f && \
    ./config && make && make install

EXPOSE 4434

# Run the vulnerable server (no -ssl2, just standard TLS)
CMD ["/usr/local/ssl/bin/openssl", "s_server", "-accept", "4433", "-key", "/root/server.key", "-cert", "/root/server.crt"]
