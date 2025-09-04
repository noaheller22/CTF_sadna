# Use an old Debian base image to make compiling old OpenSSL easier
FROM debian:7

# Install tools needed to build from source
RUN apt-get update && apt-get install -y build-essential wget perl

# Set working directory inside the container
WORKDIR /root

# Copy in RSA key and certificate from the git repo
#   - private_1024.pem: server's private key (will be used with -key)
#   - server.crt: self-signed certificate matching the key
COPY private_1024.pem /root/server.key
COPY server.crt /root/server.crt

# Download and compile OpenSSL 0.9.6 (contains SSLv2 error-message vulnerability)
RUN wget https://www.openssl.org/source/old/0.9.x/openssl-0.9.6.tar.gz && \
    tar xzf openssl-0.9.6.tar.gz && \
    cd openssl-0.9.6 && \
    ./config && make && make install

# Expose port 4433 so Docker can map it to the host
EXPOSE 4433

# Run vulnerable OpenSSL server with SSLv2 enabled
CMD ["/usr/local/ssl/bin/openssl", "s_server", "-accept", "4433", "-key", "/root/server.key", "-cert", "/root/server.crt", "-ssl2"]
