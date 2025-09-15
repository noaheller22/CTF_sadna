import argparse
import requests
import base64

SERVER_PATH = "http://nova.cs.tau.ac.il:5005"
INVALID_TEXT = ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
INVALID_CIPHER = base64.b64decode(INVALID_TEXT)

def send_cipher(cipher_candidate) :
    print("sending cipher...")
    cipher_candidate = base64.b64decode(cipher_candidate)
    requests.post(f"{SERVER_PATH}/send_cipher_1", data=cipher_candidate)
    res = requests.post(f"{SERVER_PATH}/send_cipher_2", data=INVALID_CIPHER)
    print("res.text is ", res.text)
    if res.text == "Server busy, please try again later\n" :
        print("Cipher is valid!")
        exit()
    print("Cipher is invalid!")
    exit()

def main(cipher_candidate) :
    send_cipher(cipher_candidate)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cipher_candidate")
    args = parser.parse_args()
    main(args.cipher_candidate)