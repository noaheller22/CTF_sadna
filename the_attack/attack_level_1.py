import requests
import base64
from Crypto.PublicKey import RSA
###OPTIONAL ###
from concurrent.futures import ThreadPoolExecutor 
import multiprocessing
###############

ORACLE_PATH        = "" # put the oracle path server gives you
PUBLIC_KEY_PATH    = "" # create .pem file from the key the server gives you
SECRET_CIPHER_PATH = "" # create .bin file from the cipher the server gives you
CIPHER_LENGTH      = 1024


###OPTIONAL ###
def compute_ciphertexts_parallel(c0, rsa_key, s_list, max_workers=NUM_CORES):
    """
    Computes [(c0 * s^e mod n) for s in s_list] in parallel using multiple cores.

    Inputs:
        c0          : Blinded ciphertext as int
        rsa_key     : RSA key object with (n, e)
        s_list      : List of candidate s values
        max_workers : Number of parallel threads

    Output:
        List of ciphertexts corresponding to each s in s_list
    """
    def compute_ciphertext(si):
        return ???

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(compute_ciphertext, s_list))

###############

def query_the_oracle(ciphertext, k):
    """
    This function sends a query to the oracle.
    Inputs: ciphertext as a number, the length of cipher in bytes
    Output: True for valid padding, False for invalid padding. (bool)
    """
    c_bytes = ciphertext.to_bytes(k, byteorder='big')
    b64_ciphertext = base64.b64encode(c_bytes).decode()
    response = requests.post(ORACLE_PATH, json={"ciphertext": b64_ciphertext})
    if response.status_code == 200:
        return response.json()["valid"]
    else:
        print("Error accurred reaching the oracle")
        print("cipher:")
        print(ciphertext)
        print("k:")
        print(k)
    

def query_oracle_batch(ciphertexts, k):
    """
    Sends a batch of ciphertexts to the oracle.
    Inputs: ciphertexts = list of ints, k = length of cipher in bytes.
    Output: list of booleans corresponding to each ciphertext.
    """
    b64_ciphertexts = [
        base64.b64encode(c.to_bytes(k, byteorder='big')).decode()
        for c in ciphertexts
    ]

    response = requests.post(ORACLE_PATH, json={"ciphertexts": b64_ciphertexts})
    if response.status_code == 200:
        return response.json()["valid_list"]
    else:
        print("Error occurred reaching the oracle (batch)")
        return [False] * len(ciphertexts)


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
