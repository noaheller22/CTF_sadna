import argparse
import requests
import base64

SERVER_PATH = "http://nova.cs.tau.ac.il:5004"
INVALID_TEXT = ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
INVALID_CIPHER = base64.b64decode(INVALID_TEXT)
PLAYER_ID_1 = 'alice'
PLAYER_ID_2 = 'bob'

def send_cipher(cipher_candidate) :
    print("sending cipher...")
    try :
        cipher_candidate = base64.b64decode(cipher_candidate)
    except :
        print("Something is wrong with the cipher candidate. Please try again")
        exit()
    requests.post(f"{SERVER_PATH}/send_cipher/{PLAYER_ID_1}", data=cipher_candidate)
    res = requests.post(f"{SERVER_PATH}/send_cipher/{PLAYER_ID_2}", data=INVALID_CIPHER)
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