
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random 
import os
import base64

class ctf_server() :
    def __init__(self) :
        self.MASTER_ORACLE = 5
        self.cyphers_num = 2
        self.master_message = 'YOU ARE MASTER OF ORACLES'
        self.stages_keys = {}
        for i in range(self.MASTER_ORACLE + 1):
            j = 5 ## remove this and change j to i when all oracles are created
            with open(f"private{j}.pem", "rb") as f:
                self.stages_keys[i] = RSA.import_key(f.read())
        
        ##dummies
        self.stages_hints = {
            0 : "hint1", ## stage0 oracle
            1 : "hint2", ## stage0 oracle
            2 : "hint3", ## stage0 oracle
            3 : "hint4", ## stage0 oracle
            4 : "hint5", ## stage0 oracle
            5 : "hint6"  ## master oracle (needs hint?)
        }
        self.curr_stage = {}  
        self.ports = {
            0 : 0,  ## stage0 oracle
            1 : 1,  ## stage2 oracle
            2 : 2,  ## stage3 oracle
            3 : 3,  ## stage4 oracle
            4 : 4,  ## stage5 oracle
            5 : 5   ## master oracle
        }
        self.ips = {
            0 : 6,  ## stage0 oracle
            1 : 7,  ## stage1 oracle
            2 : 8,  ## stage2 oracle
            3 : 9,  ## stage3 oracle
            4 : 10, ## stage4 oracle
            5 : 11, ## stage5 oracle
            6 : 12  ## master oracle
        }

app = Flask(__name__)
game = ctf_server()
answers = None
##Maybe add token to player so that different players can't use eachothers endpoints

@app.route("/submit/<player_id>", methods=["POST"])
def submit(player_id):
    if player_id not in game.curr_stage :
        return jsonify({"result": "fail"})
    guesses = request.json.get("guesses")
    if guesses == answers:
        game.curr_stage[player_id] +=1
        return jsonify({"result": "passed", "next_stage_ip": game.ips[game.curr_stage[player_id]], "next_stage_port": game.ports[game.curr_stage[player_id]]})
    return jsonify({"result": "fail"})

@app.route("/get_hint/<player_id>", methods=["GET"])
def get_hint(player_id):
    print("sending hint")
    if player_id not in game.curr_stage :
        game.curr_stage[player_id] = 0
    return jsonify({"hint": game.stages_hints[game.curr_stage[player_id]]})

@app.route("/get_cyphers/<player_id>", methods=["GET"])
def get_cyphers(player_id):
    if player_id not in game.curr_stage :
        game.curr_stage[player_id] = 0
    cyphers = generate_cyphers(game.stages_keys[game.curr_stage[player_id]])
    print("sending cyphers")
    return jsonify({"cyphers": cyphers})

@app.route("/get_stage/<player_id>", methods=["GET"])
def get_stage(player_id):
    if player_id not in game.curr_stage :
        game.curr_stage[player_id] = 0
    res = {"stage" : game.curr_stage[player_id], "ip": game.ips[game.curr_stage[player_id]], "port": game.ports[game.curr_stage[player_id]]}
    if game.curr_stage[player_id] == game.MASTER_ORACLE :
        res['master_message'] = gen_master_message(player_id)
    return jsonify(res)    

def generate_cyphers(private_key, count=game.cyphers_num):
    cipher = PKCS1_v1_5.new(private_key.publickey())
    key_size_bytes = private_key.size_in_bytes()
    cyphers = []
    global answers
    answers = []
    for _ in range(count):
        if random.choice([True, False]):  # coin toss: True = valid, False = invalid
            # Generate valid ciphertext by encrypting random plaintext with correct padding
            answers.append(True)
            plaintext = os.urandom(key_size_bytes - 11)  # PKCS#1 v1.5 padding overhead is 11 bytes
            valid_cypher = cipher.encrypt(plaintext)
            cyphers.append(valid_cypher)
        else:
            answers.append(False)
            # Generate invalid ciphertext by random bytes in modulus size
            invalid_num = random.randint(0, private_key.n - 1)
            invalid_cypher = long_to_bytes(invalid_num, key_size_bytes)
            cyphers.append(invalid_cypher)
    print("answers are", answers) ## for easy debugging
    cyphers_b64 = [base64.b64encode(c).decode('utf-8') for c in cyphers]
    return cyphers_b64

def gen_master_message(player_id):
    public_key = game.stages_keys[game.curr_stage[player_id]].publickey()
    cipher = PKCS1_v1_5.new(public_key)
    enc_message = cipher.encrypt(game.master_message.encode('utf-8'))
    enc_message_b64 = base64.b64encode(enc_message).decode('utf-8')
    return enc_message_b64


if __name__ == "__main__":
    game = ctf_server()
    app.run(host="0.0.0.0", port=5000)

