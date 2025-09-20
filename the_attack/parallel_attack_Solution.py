import requests
import base64
from Crypto.PublicKey import RSA
from concurrent.futures import ThreadPoolExecutor
import multiprocessing


ORACLE_PATH        = "http://localhost:5006/oracle"
PUBLIC_KEY_PATH    = "public.pem"
SECRET_CIPHER_PATH = "secret_cipher.bin" #should be .bin file
CIPHER_LENGTH      = 1024
NUM_CORES = multiprocessing.cpu_count()

s_list = []

def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def divceil(a, b):
    """
    Accurate division with ceil, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: ceil(a / b)
    """
    q, r = divmod(a, b)
    if r:
        return q + 1
    return q


def divfloor(a, b):
    """
    Accurate division with floor, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: floor(a / b)
    """
    q, r = divmod(a, b)
    return q


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

    return int.from_bytes(secret_cipher, byteorder='big')

def merge_intervals(intervals):
    """
    Merges overlapping or adjacent intervals during the Bleichenbacher attack.

    Used to maintain a minimal set of non-overlapping intervals after each oracle response,
    ensuring efficient narrowing of the plaintext search space.

    Input  : intervals        : List of tuples (a, b) with a <= b, representing valid plaintext ranges.
    Output : merged_intervals : List of non-overlapping, sorted tuples (a, b) where each a <= b and a_{i+1} > b_i.
    """

    intervals.sort(key=lambda x: x[0])

    merged_intervals = []
    curr = intervals[0]
    high = intervals[0][1]

    for interval in intervals:
        if interval[0] > high:
            merged_intervals.append(curr)
            curr = interval
            high = interval[1]
        else:
            high = max(high, interval[1])
            curr = (curr[0], high)
    merged_intervals.append(curr)

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
    s = start_s
    while True:
        c_temp = (c0 * pow(s, rsa_key.e, rsa_key.n)) % rsa_key.n
        if query_the_oracle(c_temp, k):
            s_list.append(s)
            return s
        s += 1


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
        return (c0 * pow(si, rsa_key.e, rsa_key.n)) % rsa_key.n

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(compute_ciphertext, s_list))

def find_min_conforming_batch_parallel(k, rsa_key, c0, start_s, batch_size=1200, max_workers=NUM_CORES):
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
    s = start_s

    while True:
        # Build a batch of candidate s values
        candidates = list(range(s, s + batch_size))

        # Compute ciphertexts in parallel
        ciphertexts = compute_ciphertexts_parallel(c0, rsa_key, candidates, max_workers)

        # Query oracle in one batch
        results = query_oracle_batch(ciphertexts, k)

        # Check which (if any) succeeded
        for si, res in zip(candidates, results):
            if res:
                return si

        # If none matched, continue with next batch
        s += batch_size


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

    r = divceil(2*(b*prev_s-2*B), rsa_key.n)
    while True:
        lower = divceil(2 * B + r * rsa_key.n, b)
        upper = divfloor(3 * B + r * rsa_key.n, a)
        for s in range(lower, upper + 1):
            c_temp = (c0 * pow(s, rsa_key.e, rsa_key.n)) % rsa_key.n
            if query_the_oracle(c_temp, k):
                return s
        r += 1


def search_single_interval_batch_parallel(k, rsa_key, B, prev_s, a, b, c0, batch_size=1200, max_workers=NUM_CORES):
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
    r = divceil(2 * (b * prev_s - 2 * B), rsa_key.n)

    while True:
        lower = divceil(2 * B + r * rsa_key.n, b)
        upper = divfloor(3 * B + r * rsa_key.n, a)

        # Iterate over [lower, upper] in batches
        s = lower
        while s <= upper:
            candidates = list(range(s, min(s + batch_size, upper + 1)))
            
            # Use parallel helper to compute ciphertexts
            ciphertexts = compute_ciphertexts_parallel(c0, rsa_key, candidates, max_workers)

            # Query oracle in one batch
            results = query_oracle_batch(ciphertexts, k)

            # Return the first valid s
            for si, res in zip(candidates, results):
                if res:
                    return si

            s += batch_size

        r += 1


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
    for a, b in prev_intervals:
        min_r = divceil(a * s - (3 * B - 1), rsa_key.n)
        max_r = divfloor(b * s - 2 * B, rsa_key.n)
        for r in range(min_r, max_r + 1):
            start = max(a, divceil(2 * B + r * rsa_key.n, s))
            end = min(b, divfloor(3 * B - 1 + r * rsa_key.n, s))
            intervals.append((start, end))
    return merge_intervals(intervals)

def bleichenbacher_attack(pub_key, k, secret_c, verbose=False):
    """
    Inputs: pub_key  : public key
            k        : length of ciphertext in bytes
            secret_c : ciphertext we want to decrypt in bytes
    Output: The secret message
    """

    B = 2 ** (8 * (k - 2))
    s_0 = 1
    c_0 = secret_c

    m = [(2 * B, 3 * B - 1)]

    i = 1
    
    while True:
        if verbose:
            print("Round ", i)
        if i == 1:
            s = find_min_conforming_batch_parallel(k, pub_key, c_0, divceil(pub_key.n, 3 * B))
            print("found first s:", s)
        elif len(m) > 1:
            s = find_min_conforming_batch_parallel(k, pub_key, c_0, s + 1)
        else:
            a = m[0][0]
            b = m[0][1]
            s = search_single_interval_batch_parallel(k, pub_key, B, s, a, b, c_0)

        m = narrow_m(pub_key, m, s, B)

        if len(m) == 1 and m[0][0] == m[0][1]:
            result = (m[0][0] * modinv(s_0, pub_key.n)) % pub_key.n
            break
        i += 1

    # Test the result
    print(s_list)
    if pow(result, pub_key.e, pub_key.n) == secret_c:
        return result.to_bytes(k, byteorder='big')
    else:
        return None



if __name__ == "__main__":
    pub_key = load_public_key()
    c = load_secret_cipher()
    k = (pub_key.n.bit_length() + 7) // 8 
    result = bleichenbacher_attack(pub_key, k, c, True)
    print(result)
