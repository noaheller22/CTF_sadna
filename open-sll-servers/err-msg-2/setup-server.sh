# Install build tools
sudo apt-get update
sudo apt-get install -y build-essential wget python3

# Install OpenSSL 1.0.2g
wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2g.tar.gz
tar -xzf openssl-1.0.2g.tar.gz
cd openssl-1.0.2g
./config --prefix=/usr/local/openssl-1.0.2g
make && sudo make install
cd .. && rm -rf openssl-1.0.2g*

# Verify
/usr/local/openssl-1.0.2g/bin/openssl version
# Should output: OpenSSL 1.0.2g 1 Mar 2016