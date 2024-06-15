import os
import json

cwd = os.getcwd()

def initial_print():
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

    

    print("1: View all current settings\n2: Change a setting\n3: Clear screen")

initial_print()
config_file_path = os.path.join(cwd , "config.json")
while True:
    option = input("Enter your option: ")
    if option == "1":

        f = open(config_file_path , "r")
        configs = json.loads(f.read())
        f.close()
        for key in configs:
            print(f"{key}:{configs[key]}")

    elif option == "2":
        f = open(config_file_path , "r")
        configs = json.loads(f.read())
        f.close()

        config_to_change = input("Which setting do you want to change: ")
        if config_to_change not in configs:
            print("[!] NO SUCH CONFIG SETTING AVAILABLE")
        else:
            new_value = input("What do you want the new value of the config to be: ")
            configs[config_to_change] = new_value
            f = open(config_file_path , "w")
            f.write(json.dumps(configs))
            f.close()
            print("[!] CONFIGURATION CHANGED SUCCESSFULLY")

    elif option == "3":
        initial_print()
    else:
        print("[!] INVALID OPTION")