# For the openSLL servers we will use nova VE
# Nova's public ip that will be exposed to the player is 132.67.247.151
# Ports:
    * For the error message server we will use port 4433
    * For the timing server we will use port 4434

# Setting up and Running the servers:
    * Go into the folder of the server you want to run.
        1. Run chmod +x setup_vuln_openssl.sh and chmod +x run_vuln_server.sh
        2. Run ./setup_vuln_openssl.sh
    * For each server start by running setup_vuln_openssl.sh for set up
    * After running the setup script run:
        1. To run the err msg server - "~/openssl-0.9.6/apps/openssl s_server -accept 4433 -key ~/CTF_sadna/open-sll-servers/err-msg/private_1024.pem -cert ~/CTF_sadna/open-sll-servers/err-msg/server.crt -ssl2"
        2. To run the timing server - "~/openssl-1.0.1f/apps/openssl s_server -accept 4434 -key ~/CTF_sadna/open-sll-servers/timing/private_1024.pem -cert ~/CTF_sadna/open-sll-servers/timing/server.crt
"