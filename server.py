
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random 
import os
import base64
from base64 import b64encode

class ctf_server() :
    def __init__(self) :
        self.MASTER_ORACLE = 5
        self.ciphers_num = 10
        self.master_message = 'YOU ARE MASTER OF ORACLES'
        self.stages_keys = {}
        for i in range(self.MASTER_ORACLE + 1):
            with open(f"private{i+1}.pem", "rb") as f:
                self.stages_keys[i] = RSA.import_key(f.read())
        
        self.stages_hints = {
            0 : [], ## Error-messages server
            1 : [], ## Timing server
            2 : ["Wireshark"], ## TCP server
            3 : ["Two is better than one"], ## Cooperation server
            4 : [], ## Cache server
        }
        clues_folders = {
            "./open-ssl-servers/Error-Message-Vulnerability/clues/" : 0,
            "./open-ssl-servers/Timing-Vulnerability/clues/" : 1,
            "./cache_server/clues/" : 4
        }

        for folder in clues_folders.keys() : 
            clues = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
            for i in range(len(clues)) : 
                with open(os.path.join(folder,clues[i]), "r", encoding="utf-8") as f:
                    self.stages_hints[clues_folders[folder]].append(f.read())

        self.curr_stage = {}  

        self.URLs = {
            0 : "nova.cs.tau.ac.il:5001" ,
            1 : "nova.cs.tau.ac.il:5002" ,
            2 : "nova.cs.tau.ac.il:5003" ,
            3 : "http://nova.cs.tau.ac.il:5004/send_cipher, http://nova.cs.tau.ac.il:5003/check_status" ,
            4 : "http://nova.cs.tau.ac.il:5005/config, http://nova.cs.tau.ac.il:5005/write, http://nova.cs.tau.ac.il:5005/read, http://nova.cs.tau.ac.il:5005/oracle" ,
            5 : "http://nova.cs.tau.ac.il:5006/oracle"
        }

app = Flask(__name__)
game = ctf_server()
answers = None

@app.route("/submit/<player_id>", methods=["POST"])
def submit(player_id):
    if player_id not in game.curr_stage :
        return jsonify({"result": "fail"})
    guesses = request.json.get("guesses")
    if guesses == answers:
        game.curr_stage[player_id] +=1
        next_key = game.stages_keys[game.curr_stage[player_id]].publickey().export_key(format="PEM")
        res = {
            "result": "passed",     
            "next_stage_URL": game.URLs[game.curr_stage[player_id]], 
            "public_key": next_key.decode()
        }
        return jsonify(res)
    return jsonify({"result": "fail"})

@app.route("/get_hint/<player_id>", methods=["GET"])
def get_hint(player_id):
    if player_id not in game.curr_stage :
        game.curr_stage[player_id] = 0
    return jsonify({"hint": game.stages_hints[game.curr_stage[player_id]]})

@app.route("/get_ciphers/<player_id>", methods=["GET"])
def get_ciphers(player_id):
    if player_id not in game.curr_stage :
        game.curr_stage[player_id] = 0
    ciphers = generate_ciphers(game.stages_keys[game.curr_stage[player_id]])
    print("sending ciphers")
    return jsonify({"ciphers": ciphers})

@app.route("/get_stage/<player_id>", methods=["GET"])
def get_stage(player_id):
    if player_id not in game.curr_stage :
        game.curr_stage[player_id] = 0

    res = {
    "stage": game.curr_stage[player_id],
    "URL": game.URLs[game.curr_stage[player_id]],
    "public_key": game.stages_keys[game.curr_stage[player_id]].publickey().export_key(format="PEM").decode()
    }
    if game.curr_stage[player_id] == game.MASTER_ORACLE :
        res['master_message'] = gen_master_message(player_id)
        for i in range(1,4) :
            with open(f"./the_attack/attack_level_{i}.py", "r", encoding="utf-8") as f:
                res[f'final_attack_{i}'] = f.read() 
    return jsonify(res)

def generate_ciphers(private_key, count=game.ciphers_num):
    cipher = PKCS1_v1_5.new(private_key.publickey())
    key_size_bytes = private_key.size_in_bytes()
    ciphers = []
    global answers
    answers = []
    for _ in range(count):
        if random.choice([True, False]):  # coin toss: True = valid, False = invalid
            # Generate valid ciphertext by encrypting random plaintext with correct padding
            answers.append(True)
            plaintext = os.urandom(key_size_bytes - 11)  # PKCS#1 v1.5 padding overhead is 11 bytes
            valid_cipher = cipher.encrypt(plaintext)
            ciphers.append(valid_cipher)
        else:
            answers.append(False)
            # Generate invalid ciphertext by random bytes in modulus size
            is_valid = True
            while is_valid : ##Make sure cipher is not "accidentaly" valid 
                invalid_num = random.randint(0, private_key.n - 1)
                invalid_cipher = long_to_bytes(invalid_num, key_size_bytes)
                cipher = PKCS1_v1_5.new(private_key)
                result = cipher.decrypt(invalid_cipher, None)
                is_valid = result != b''
            ciphers.append(invalid_cipher)
    print("answers are", answers) ## for easy debugging - remove when done!
    ciphers_b64 = [base64.b64encode(ciphertext).decode() for ciphertext in ciphers]
    return ciphers_b64


def gen_master_message(player_id):
    """
    Encrypts the master message for a given player and returns a copyable Base64 string.
    """
    # Get the public key for the current stage of the player
    public_key = game.stages_keys[game.curr_stage[player_id]].publickey()
    
    # Create cipher object
    cipher = PKCS1_v1_5.new(public_key)
    
    # Encrypt the master message (UTF-8 encoded)
    enc_bytes = cipher.encrypt(game.master_message.encode('ascii'))
    
    # Encode the ciphertext in Base64 (ASCII safe) for copy/paste
    enc_b64 = base64.b64encode(enc_bytes).decode('ascii')
    
    return enc_b64


if __name__ == "__main__":
    game = ctf_server()
    app.run(host="0.0.0.0", port=5000)

