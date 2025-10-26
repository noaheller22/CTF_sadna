
import random as rand
import requests
import base64
import argparse

##################################
### Please choose a player_id ####
PLAYER_ID = "alice"
##################################

BACKEND_URL = "http://nova.cs.tau.ac.il:5000"

class CTF () :
    def __init__(self):  
        self.stage = 0
        self.MASTER_ORACLE = 5
        self.order = {
            1 : "first",
            2 : "second",
            3 : "third"
        }
        self.hint_num = 0
        self.curr_URL = None
        self.curr_pb = None 

    def get_stage(self) :
        res = requests.get(f"{BACKEND_URL}/get_stage/{PLAYER_ID}").json()
        return res['stage'], res['URL'], res['public_key']
    
    def get_hint(self) :
        res = requests.get(f"{BACKEND_URL}/get_hint/{PLAYER_ID}").json()
        if game.hint_num >= len(res['hint']) :
            print("You have reached the maximum hints number. Printing all hints:\n")
            for i in range(len(res['hint'])) :
                print(f"hint {i}:\n{res['hint'][i]}\n")
        else : 
            print(f"Your {game.order[game.hint_num + 1]} hint is:\n{res['hint'][game.hint_num]}\n")
            game.hint_num+=1

    
    def test_oracle(self, URL, public_key) :
            print("You are going to be presented with a number of ciphers. \n"\
            "For each one, decide whether the cipher has valid padding or not based on your oracle. \n"\
            "Don't worry, you can still print details with 'd' and hint with 'h\n")
            ciphers = self.get_ciphers()
            guesses = []
            i = 0
            while i < len(ciphers) :
                cipher = ciphers[i]
                print(f"Does this cipher have valid padding? Reply [y\\n]:\n",cipher)
                cmd = input(">>> ").strip().lower()
                if cmd == 'y' : 
                    i +=1
                    guess = True
                    guesses.append(guess)
                elif cmd == 'n' :
                    guess = False
                    i +=1
                    guesses.append(guess)
                elif cmd == 'd' : 
                    print("\033[2J\033[H", end="")
                    print(f"""server you need to defeat is:
URL: {self.curr_URL} \nPublic Key:\n{self.curr_pb}""")
                elif cmd == 'h' : 
                    print("\033[2J\033[H", end="")
                    game.get_hint()    
                else : 
                    print("Not a valid character. Lets try again:")
            res = requests.post(f"{BACKEND_URL}/submit/{PLAYER_ID}", json={"guesses": guesses})
            data = res.json()
            print("\033[2J\033[H", end="")
            if data["result"] == "passed":
                print(f"Stage passed!")
                self.stage +=1
                self.hint_num = 0
                if self.stage != game.MASTER_ORACLE :
                    print(f"Access next stage with URL {data['next_stage_URL']}")
                    print(f"The server's public key is: \n")
                    print(data['public_key'])
                    self.curr_pb = data['public_key']
                    self.curr_URL = data['next_stage_URL']
            else:
                print("Stage failed. You lost.")
                exit()
    
    def last_stage(self) :
        res = requests.get(f"{BACKEND_URL}/get_stage/{PLAYER_ID}").json()
        if res['stage'] != game.MASTER_ORACLE :
            print("wrong stage!")
            exit()
        print(f"""************ \nThis is your chance to prove your worth.\n
Prepare your bleichenbacher attack, and attack using the master oracle!\n
URL: {res['URL']}\n 
Public Key: {res['public_key']}\n
Decipher the following message by completing the given attack.\n
The message: \n{res['master_message']}
Choose the help level [1/2/3]:\n 
level 1: help functions + minimal sceleton\n
level 2: level 1 + detailed sceleton\n
level 3: level 2 + partial implementaion\n""")
        while True : 
            print("Choose your level:")
            cmd = input(">>> ").strip().lower()
            if cmd not in ['1','2','3'] :
                print("Invalid level. Choose [1/2/3]")
            else : 
                print("Use the following code:\n")
                print(res[f'final_attack_{cmd}'])
                print("Would you like to change level? [y/n]")
                cmd = input(">>> ").strip().lower()
                if cmd == 'n' :
                    break
                if cmd != 'y' :
                    print("Not a valid character. Lets try again:")
        print(f"""We guess you solved our CTF. If you got the right answer, trust us - you'll know.\n
Goodbye!""")
        exit() 

    def get_ciphers(self) :
        res = requests.get(f"{BACKEND_URL}/get_ciphers/{PLAYER_ID}").json()
        return res['ciphers']


game = CTF()

def main(save_path):
    if PLAYER_ID == "" :
        print("Please write your player id in the code and run client.py again")
        exit()
    stage, URL, public_key = game.get_stage()
    game.stage = stage
    if stage == 0:
        print("Welcome to ctf game: Order of the Oracles. Would you like to begin? reply [y\\n]")
    else :
        print(f"Welcome back! you are in stage {stage + 1}, URL: {URL}. public key is:\n{public_key}")
        main_menu(URL, public_key)
    command = input(">>> ").strip()
    if command.lower() == 'y' :
        print(f"""Great! lets Start. The first server you need to defeat is:
URL: {URL} \nPublic Key:\n{public_key}""")
        main_menu(URL, public_key)

def main_menu(URL, public_key):
    self.curr_pb = public_key
    self.curr_URL = URL
    while True: 
        if game.stage == game.MASTER_ORACLE :
            game.last_stage() 
        print(f"\nGet a hint (some servers have more than one hint): H\n" \
        "Test my oracle to continue to the next stage: T\n" \
        "Print stage details: d\n")
        cmd = input(">>> ").strip().lower()  
        if cmd == "h":
            print("\033[2J\033[H", end="")
            game.get_hint()
        elif cmd == "t":
            print("\033[2J\033[H", end="")
            game.test_oracle(URL, public_key)
        elif cmd == "d" :
            print("\033[2J\033[H", end="")
            print(f"""server you need to defeat is:
URL: {self.curr_URL} \nPublic Key:\n{self.curr_pb}""")
        else : 
            print("Not a valid charachter. Try again.")              

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--save_path")
    args = parser.parse_args()
    main(args.save_path)
