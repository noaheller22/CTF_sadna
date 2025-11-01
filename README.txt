Instructions for players: 

CTF Challange - ORDER OF THE ORACLES 
To run the challange please: 

1. Make sure requests and crypto packages are installed
2. Run ./client.py on your PC 

user_help_functions folder contains some wrappers to help with different stages and the game in general. 

Genral instructions for CTF: 
1. server.py should be run on a remote host (configured on client and skeleton functions to be Nova server).
2. server.py runs all of the vulnerable servers on the remote host upon its initialization.
3. Each directory contains each stage's relevant files, including the server itself and the oracle solution (error and timining servers are inside open-ssl-servers directory).
4. The client should have on its local computer both the client.py (which it needs to run to start the game), and the user_help_functions.
