import requests
import base64
from Crypto.PublicKey import RSA

ORACLE_PATH        = "http://localhost:5000/oracle"
PUBLIC_KEY_PATH    = "public.pem"
SECRET_CIPHER_PATH = "" #should be .bin file
CIPHER_LENGTH      = 1024


def query_the_oracle(ciphertext):
	"""
	This function sends a query to the oracle.
	Inputs: ciphertext in bytes. 
	Output: True for valid padding, False for invalid padding. (bool)
	"""
	b64_ciphertext = base64.b64encode(ciphertext).decode()
	response = requests.post(ORACLE_PATH, json={"ciphertext": b64_ciphertext})

	return response.json()["valid"]

def load_public_key():
	"""
	Output: the public key. make sure the PUBLIC_KEY_PATH is well define!
	"""
	with open(PUBLIC_KEY_PATH, "rb") as key_file:
	    pub_key = RSA.import_key(key_file.read())

	return pub_key

def load_secret_cipher():
	"""
	Output: the secret cipher. make sure the SECRET_CIPHER_PATH is well define!
	"""

	with open(SECRET_CIPHER_PATH, "rb") as cipher_file:
	    secret_cipher = cipher_file.read()

	return secret_cipher

def bleichenbacher_attack(pub_key, l, secret_c):
    """
    Inputs: pub_key  : public key
    		l        : length of ciphertext in bytes
    		secret_c : ciphertext we want to decrypt in bytes
    Output: The secret message
    """

    """
    YOUR CODE HERE
    """

    return secret_message


if __name__ == "__main__":
    l = int(CIPHER_LENGTH / 8) 
    pub_key = load_public_key()
    c = load_secret_cipher()
    result = bleichenbacher_attack(pub_key, l, c)
    print(result)
