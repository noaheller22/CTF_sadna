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

def merge_intervals(intervals):
    """
    Merges overlapping or adjacent intervals during the Bleichenbacher attack.

    Used to maintain a minimal set of non-overlapping intervals after each oracle response,
    ensuring efficient narrowing of the plaintext search space.

    Input  : intervals        : List of tuples (a, b) with a <= b, representing valid plaintext ranges.
    Output : merged_intervals : List of non-overlapping, sorted tuples (a, b) where each a <= b and a_{i+1} > b_i.
    """

    return merged_intervals

def find_min_conforming(k, rsa_key, c0, start_s):
    """
    Finds the smallest 's' such that the modified ciphertext is PKCS#1 v1.5 conforming.

    Iterates s ≥ start_s until (c0 * s^e mod n) passes the oracle check.

    Inputs : k       : RSA modulus length in bytes.
             rsa_key : RSA key object with (n, e).
             c0      : The initial ciphertext as an integer (c0 = (c * s0^e mod n)).
             start_s : Starting value of s to search from.
    Output : s       :The smallest integer s ≥ start_s such that oracle((c0 * s^e) mod n) is True.
    """

    return s

def find_min_conforming_batch_parallel(k, rsa_key, c0, start_s, batch_size=500, max_workers=NUM_CORES):
    """
    Finds the smallest 's' such that the modified ciphertext is PKCS#1 v1.5 conforming.

    Uses batching to reduce oracle overhead and parallel computation for RSA.

    Inputs:
        k          : RSA modulus length in bytes
        rsa_key    : RSA key object with (n, e)
        c0         : Initial ciphertext as an int (c0 = c * s0^e mod n)
        start_s    : Starting value of s to search from
        batch_size : Number of candidates to send to oracle per request
        max_workers: Number of parallel workers for computing s^e mod n

    Output:
        s : The smallest integer >= start_s such that oracle((c0 * s^e mod n)) is True
    """
    return s

def search_single_interval(k, rsa_key, B, prev_s, a, b, c0):
    """
    Searches for the next valid 's' when only one interval remains.

    Exploits the reduced search space (a single interval) to find the next 's'
    such that (c0 * s^e mod n) is PKCS#1 v1.5 conforming.

    Inputs : k       : RSA modulus length in bytes.
             rsa_key : RSA key object with (n, e).
             B       : Boundary constant- 2^(8 * (k - 2)).
             prev_s  : s value from the previous iteration.
             a       : Lower bound of the remaining interval.
             b       : Upper bound of the remaining interval.
             c0      : Blinded ciphertext (c0 = c * s0^e mod n).
    Output : s       : A new s ≥ prev_s such that oracle((c0 * s^e) mod n) returns True.
    """

    return s

def search_single_interval_batch_parallel(k, rsa_key, B, prev_s, a, b, c0, batch_size=500, max_workers=NUM_CORES):
    """
    Searches for the next valid 's' when only one interval remains.

    Uses batching and parallel computation to minimize oracle queries.

    Inputs:
        k          : RSA modulus length in bytes
        rsa_key    : RSA key object with (n, e)
        B          : Boundary constant = 2^(8 * (k - 2))
        prev_s     : Previous 's' value
        a, b       : Bounds of the remaining interval
        c0         : Blinded ciphertext (c0 = c * s0^e mod n)
        batch_size : Number of candidates to query per request
        max_workers: Number of parallel threads for RSA computation

    Output:
        s : A new 's' ≥ prev_s such that oracle((c0 * s^e mod n)) is True
    """
    return s

def narrow_m(rsa_key, prev_intervals, s, B):
    """
    Updates the set of intervals (M) based on the current valid s.

    Given the previous set of intervals and the current s, computes the new intervals
    [a, b] such that the corresponding plaintext m = (c0 * s^e mod n) lies within
    the valid PKCS#1 v1.5 range (i.e., 2B ≤ m < 3B).

    Inputs : rsa_key        : RSA key object with modulus n.
             prev_intervals : List of tuples (a, b) representing the previous valid ranges of m.
             s              : The s value found in the current round.
             B              : Boundary constant- B = 2^(8 * (k - 2)).
    Output : A new list of narrowed intervals (a, b) for the next iteration.
    """
    intervals = []

    return merge_intervals(intervals)

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
