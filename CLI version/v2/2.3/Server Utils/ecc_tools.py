from Crypto.PublicKey import ECC
import os
import json
import pwinput
from Crypto.Cipher import PKCS1_OAEP
import secrets
import random
import gc
import time


cwd = os.getcwd()

os.system("cls")
print("0xChat ECC Tools [Server Side]")
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

ecc_private_key_path = os.path.join(cwd , "ecc_private_key.aplyn")
ecc_public_key_path = os.path.join(cwd , "ecc_public_key.aplyn")

print("1: View private key\n2: View public key\n3: Change/Create private and public key \n4: Purge keys \n5: Clear screen")
while True:
    option = input("Enter your option: ")
    if option == "1":
        if os.path.isfile(ecc_private_key_path):
            f = open(ecc_private_key_path , "r")
            ecc_priv_key = f.read()
            f.close()
            if ecc_priv_key == "":
                print("[!] NO PRIVATE KEY FOUND, PLEASE GENERATE ONE")
            else:
                password = pwinput.pwinput(prompt='Enter password to access the key: ', mask='*')
                password = password.encode()
                with open(ecc_private_key_path, "rt") as f:
                    key_data = f.read()
                    ecc_priv_key = ECC.import_key(key_data, password)
                print(ecc_priv_key)
        else:
            print("[!] NO PRIVATE KEY FOUND, PLEASE GENERATE ONE")

    elif option == "2":
        if os.path.isfile(ecc_public_key_path):
            f = open(ecc_public_key_path , "r")
            ecc_public_key = f.read()
            f.close()
            if ecc_public_key == "":
                print("[!] NO PUBLIC KEY FOUND, PLEASE GENERATE ONE")
            else:
                with open(ecc_public_key_path, "rt") as f:
                    ecc_public_key = ECC.import_key(f.read())
                    f.close()
                print(ecc_public_key)   
        else:
            print("[!] NO PUBLIC KEY FOUND, PLEASE GENERATE ONE")
    elif option == "3":

        confirmation = input("[!] ARE YOU SURE YOU WANT TO GENERATE AN ECC PUBLIC-PRIVATE KEY PAIR ? IF YOU HAVE ANY PRIOR KEYS, THEY WILL BE OVERWRITTEN. [y/N]")
        if confirmation.lower() == "y":
            password = pwinput.pwinput(prompt='Enter password to secure the key [FORGETTING THE PASSWORD WILL LEAD TO LOSS OF THE KEY]: ', mask='*')
            password = password.encode()
            new_private_key = ECC.generate(curve='p521')
            with open(ecc_private_key_path, "wt") as f:
                data = new_private_key.export_key(format='PEM' , passphrase=password , protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', prot_params={'iteration_count':131072})
                f.write(data)
                f.close()
            with open(ecc_public_key_path, "wt") as f:
                data = new_private_key.public_key().export_key(format='PEM')
                f.write(data)
                f.close()

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
        print("1: View private key\n2: View public key\n3: Change/Create private and public key \n4: Purge keys \n5: Clear screen")

    elif option == "4":

        file_size_priv = os.path.getsize(ecc_private_key_path)
        file_size_public = os.path.getsize(ecc_public_key_path)
        for i in range(random.randint(128,256)):
            overwriting_private_key = secrets.token_bytes(file_size_priv)
            overwriting_public_key = secrets.token_bytes(file_size_public)
            f = open(ecc_private_key_path , "wb")
            f.write(overwriting_private_key )
            f.close()
            del f
            del overwriting_private_key
            f = open(ecc_public_key_path , "wb")
            f.write(overwriting_public_key)
            f.close()
            del f
            del overwriting_public_key
        os.remove(ecc_private_key_path)
        os.remove(ecc_public_key_path)
        print("[!] PURGED PRIVATE KEYS")
        f = open(ecc_private_key_path , "w")
        f.write("")
        f.close()
        del f
        f = open(ecc_public_key_path , "w")
        f.write("")
        f.close()
        del f
        gc.collect()
        print("[!] CLEARING CONSOLE OUTPUT")
        gc.collect()

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
        print("1: View private key\n2: View public key\n3: Change/Create private and public key \n4: Purge keys \n5: Clear screen")

    else:
        print("[!]INVALID COMMAND")


        




 




