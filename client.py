
import random as rand
import requests
import base64

BACKEND_URL = "http://nova.cs.tau.ac.il:5000"
PLAYER_ID = "alice"  
### For now cyphers are printed to terminal. Might need to change to writing to file
class CTF () :
    def __init__(self):  
        self.stage = 0
        self.MASTER_ORACLE = 5

    def get_stage(self) :
        res = requests.get(f"{BACKEND_URL}/get_stage/{PLAYER_ID}").json()
        return res['stage'], res['ip'] , res['port']
    
    def get_hint(self) :
        res = requests.get(f"{BACKEND_URL}/get_hint/{PLAYER_ID}").json()
        print(f"Your hint is:\n {res['hint']}")
    
    def test_oracle(self) :
            print("You are going to be presented with a number of ciphers. \n"\
            "For each one, decide whether the cipher has valid padding or not based on your oracle.")
            cyphers = self.get_cyphers()
            guesses = []
            i = 0
            while i < len(cyphers) :
                cypher = cyphers[i]
                print(f"Does this cipher have valid padding? Reply [y\\n]:\n",cypher)
                cmd = input(">>> ").strip().lower()
                if cmd == 'y' : 
                    i +=1
                    guess = True
                elif cmd == 'n' :
                    guess = False
                    i +=1
                else : 
                    print("Not a valid charachter. Lets try again:")
                guesses.append(guess)
            res = requests.post(f"{BACKEND_URL}/submit/{PLAYER_ID}", json={"guesses": guesses})
            print("guesses are ", guesses) 
            data = res.json()
            print("resuls are ", data['result'])
            if data["result"] == "passed":
                print(f"Stage passed!")
                self.stage +=1
                if self.stage != game.MASTER_ORACLE :
                    print(f"Access next stage with ip {data['next_stage_ip']} and port {data['next_stage_port']}")
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
ip: {res['ip']} port: {res['port']}\n 
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
        print(f"""We guess you solved our CTF. If you got the right answer, trust us - you'll know.\n
Goodbye!""")
        exit() 
        ### Can add a check with server this is the correct message, for now it's obvious (player has to do recovered_plaintext.decode('utf-8') first)

    def get_cyphers(self) :
        res = requests.get(f"{BACKEND_URL}/get_cyphers/{PLAYER_ID}").json()
        decoded_cyphers = [base64.b64decode(c) for c in res['cyphers']]
        return decoded_cyphers


game = CTF()

def main():
    stage, ip, port = game.get_stage()
    game.stage = stage
    if stage == 0:
        print("Welcome to ctf game: Order of the Oracles. Would you like to begin? reply [y\\n]")
    else :
        print(f"Welcome back! you are in stage {stage}, ip: {ip}, port: {port}")
        main_menu()
    command = input(">>> ").strip()
    if command.lower() == 'y' :
        print(f"""Great! lets Start. The first server you need to defeat is:
ip: {ip} port: {port}""")
        main_menu()

def main_menu():
    while True: 
        if game.stage == game.MASTER_ORACLE :
            game.last_stage() 
        print(f"Get a hint: H\n" \
        "Test my oracle to continue to the next stage: T\n")
        cmd = input(">>> ").strip().lower()  
        if cmd == "h":
            game.get_hint()
        elif cmd == "t":
            game.test_oracle()
        else : 
            print("Not a valid charachter. Try again.")              

if __name__ == "__main__":
    main()
