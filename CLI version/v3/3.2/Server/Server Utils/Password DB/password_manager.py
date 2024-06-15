import os
import json

cwd = os.getcwd()

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")
    
print("0xChat Server Utils")
print("Made by 0xApollyon")
print("twitter.com/0xApollyon\n")

print(r"""
_______         _________ .__            __   
\   _  \ ___  __\_   ___ \|  |__ _____ _/  |_ 
/  /_\  \\  \/  /    \  \/|  |  \\__  \\   __\
\  \_/   \>    <\     \___|   Y  \/ __ \|  |  
 \_____  /__/\_ \\______  /___|  (____  /__|  
       \/      \/       \/     \/     \/      

""")

pass_file_path = os.path.join(cwd , "passwords.json")

print("1: View all password hashes\n2: Add a user-password pair\n3: Remove a user-password pair \n4: Change a user-password pair \n5: Clear screen")
while True:
    option = input("Enter your option: ")
    if option == "1":
        f = open(pass_file_path, "r")
        passwords = f.read()
        f.close()
        try:
            passwords = json.loads(passwords)
        
            if len(passwords) == 0:
                print("[!] NO USER PASSWORDS FOUND")  
            else:
                for user in passwords:
                    print(f"{user}: {passwords[user]}")
        except:
            print("[!] NO USER PASSWORDS FOUND")                

    elif option == "2":
        f = open(pass_file_path, "r")
        passwords = f.read()
        f.close()

        username = input("Enter username to add: ").strip()
        pass_hash = input("Enter sha256 password hash of the user: ").strip()

        passwords = json.loads(passwords)
        passwords[username] = pass_hash

        f = open(pass_file_path, "w")
        f.write(json.dumps(passwords))
        f.close()

    elif option == "3":

        f = open(pass_file_path, "r")
        passwords = f.read()
        f.close()

        username = input("Enter username to remove: ").strip()
        passwords = json.loads(passwords)

        if username in passwords.keys():


            del passwords[username]

            f = open(pass_file_path, "w")
            f.write(json.dumps(passwords))
            f.close()
        else:
            print("[!] No username found")

    elif option == "4":

        f = open(pass_file_path, "r")
        passwords = f.read()
        f.close()

        username = input("Enter username to change: ").strip()
        passwords = json.loads(passwords)

        if username in passwords.keys():

            new_hash = input("Enter new password hash: ").strip()

            passwords[username] = pass_hash

            f = open(pass_file_path, "w")
            f.write(json.dumps(passwords))
            f.close()
        else:
            print("[!] No username found")

    elif option == "5":

        os.system("cls")
        print("0xChat Server Utils")
        print("Made by 0xApollyon")
        print("twitter.com/0xApollyon\n")

        print(r"""
_______         _________ .__            __   
\   _  \ ___  __\_   ___ \|  |__ _____ _/  |_ 
/  /_\  \\  \/  /    \  \/|  |  \\__  \\   __\
\  \_/   \>    <\     \___|   Y  \/ __ \|  |  
 \_____  /__/\_ \\______  /___|  (____  /__|  
       \/      \/       \/     \/     \/  

            """)

        print("1: View all password hashes\n2: Add a user-password pair\n3: Remove a user-password pair \n4: Change a user-password pair \n5: Clear screen1")

    else:
        print("[!]INVALID OPTION")




    




    



