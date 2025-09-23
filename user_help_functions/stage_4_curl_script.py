
#######################################
### Helper curl script for stage 4 ####
#######################################

import base64
import requests
import argparse

def send_cipher(cipher_b64, URL):
    if cipher_b64 == None : 
        print("No cipher was given. Assuming check_status...")
        response = requests.get(URL)
    else : 
        # Decode Base64 to raw bytes
        try : 
            cipher_bytes = base64.b64decode(cipher_b64)
        except :
            print("curl_script: Something is wrong with your cipher. Try again")
            return
        
        # Send raw bytes to the server
        response = requests.post(URL, data=cipher_bytes)
        
    print("Server response:")
    print(response.text)

def main(cipher_candidate, URL) :
    send_cipher(cipher_candidate, URL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cipher_candidate")
    parser.add_argument("--URL")
    args = parser.parse_args()
    main(args.cipher_candidate, args.URL)