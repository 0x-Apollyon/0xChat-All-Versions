print("0xChat CLI Mode")
print("v2.3")
print("Made by 0xApollyon")
print("twitter.com/0xApollyon\n")

import socket
import hashlib 
import sys
import os
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pwinput


cwd = os.getcwd()
client_utils_path = os.path.join(cwd , "Client Utils")
client_config_path = os.path.join(client_utils_path , "server_logs.aplyn")




save_load = input("Fast connect to a saved server [y/N]: ")
if save_load.lower() == "y":
    alias_save = input("Enter alias to fast connect: ").strip().lower()

    f = open(client_config_path , "r")
    saved_server_list = f.read()
    f.close()

    saved_server_list = eval(saved_server_list)
    for server in saved_server_list:
        saved_server_info = json.loads(server)
        if saved_server_info["alias"] == alias_save:
            server = saved_server_info["server_ip"]
            port = saved_server_info["server_port"]
            username = saved_server_info["username"]
            
            if "pass_hash" in saved_server_info:
                pass_hash = saved_server_info["pass_hash"]


else:
    
    username = input("Enter your username to connect: ")
    server = input("Enter server ip: ")
    port = int(input("Enter port to connect: "))
    password = input("Enter your password (required to connect to secure servers): ")
    to_save = input("Want to save this server to the fast connect list (TO SAVE PASSWORD AS WELL USE THIRD OPTION) [y/N/yp]: ")

    pass_hash = hashlib.sha256(password.encode()) 
    pass_hash = pass_hash.hexdigest()

    if to_save.lower() == "y":
        alias = input("Enter alias to save server to fast connect list: ").strip().lower()
        jbeta = {
            "alias": alias,
            "server_ip": server,
            "server_port": port,
            "username": username
        }
        f = open(client_config_path , "r")
        saved_server_list = f.read()
        f.close()

        saved_server_list = eval(saved_server_list)
        saved_server_list.append(json.dumps(jbeta))

        f = open(client_config_path , "w")
        f.write(saved_server_list)
        f.close()

    elif to_save.lower() == "yp":
        alias = input("Enter alias to save server to fast connect list: ").strip().lower()
        jbeta = {
            "alias": alias,
            "server_ip": server,
            "server_port": port,
            "username": username,
            "pass_hash": pass_hash
        }

        f = open(client_config_path , "r")
        saved_server_list = f.read()
        f.close()

        saved_server_list = eval(saved_server_list)
        saved_server_list.append(json.dumps(jbeta))

        f = open(client_config_path , "w")
        f.write(json.dumps(saved_server_list))
        f.close()


os.system("cls")



print(r"""
_______         _________ .__            __   
\   _  \ ___  __\_   ___ \|  |__ _____ _/  |_ 
/  /_\  \\  \/  /    \  \/|  |  \\__  \\   __\
\  \_/   \>    <\     \___|   Y  \/ __ \|  |  
 \_____  /__/\_ \\______  /___|  (____  /__|  
       \/      \/       \/     \/     \/      

""")



sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((server, port))

print(f"Connected to server --> {server}:{port}")
init_data = sock.recv(2048).decode()
init_data = init_data.split("|")
secure_mode = init_data[1]
if init_data[2] == "SYM-ENCRYPTION:ENABLED":
    server_side_encryption = True
    rsa_public_key_path = os.path.join(client_utils_path , "rsa_public_key.aplyn")
    rsa_private_key_path = os.path.join(client_utils_path , "rsa_private_key.aplyn")

    server_public_key = init_data[3].replace("RSA-KEY:" , "")
    server_public_key = RSA.import_key(server_public_key)
    server_cipher_rsa = PKCS1_OAEP.new(server_public_key)    

    if os.path.isfile(rsa_public_key_path):
        f = open(rsa_public_key_path , "r")
        rsa_public_key = f.read()
        f.close()
        if rsa_public_key == "":
            print("[!] SERVER HAS SERVER-SIDE ENCRYPTION ENABLED. PLEASE GENERATE A RSA-4096 KEY PAIR USING CLIENT TOOLS")
            quit()
        else:
            with open(rsa_public_key_path, "rt") as f:
                rsa_public_key_raw = f.read()
                rsa_public_key = RSA.import_key(rsa_public_key_raw)
    else:
        print("[!] SERVER HAS SERVER-SIDE ENCRYPTION ENABLED. PLEASE GENERATE A RSA-4096 KEY PAIR USING CLIENT TOOLS")
        quit()

    if os.path.isfile(rsa_private_key_path):
        f = open(rsa_private_key_path , "r")
        rsa_private_key = f.read()
        f.close()

        if rsa_private_key == "":
            print("[!] SERVER HAS SERVER-SIDE ENCRYPTION ENABLED. PLEASE GENERATE A RSA-4096 KEY PAIR USING CLIENT TOOLS")
            quit()
        else:
            password = pwinput.pwinput(prompt='Enter password to access the key: ', mask='*')
            password = password.encode()
            try:
                with open(rsa_private_key_path, "rb") as f:
                    key_data = f.read()
                    rsa_priv_key = RSA.import_key(key_data, passphrase=password)
                    rsa_priv_cipher = PKCS1_OAEP.new(rsa_priv_key)
            except:
                print("[!] ERROR IMPORTING PRIVATE KEY, CHECK IF YOUR PASSWORD IS CORRECT")
                quit()
    else:
        print("[!] SERVER HAS SERVER-SIDE ENCRYPTION ENABLED. PLEASE GENERATE A RSA-4096 KEY PAIR USING CLIENT TOOLS")
        quit()

    rsa_message = f"---CLIENT-RSA-KEY---|{rsa_public_key_raw}"
    sock.sendall(rsa_message.encode())
if secure_mode.lower() == "securemode:enabled":
    secure_mode = True
else:
    secure_mode = False



def rec_messages(sock):
    while True:
        if server_side_encryption:
            data = sock.recv(2048)
            if data:
                if data == "INVALID PASSWORD":
                    print("Invalid password , quitting")
                    quit()
                else:
                    data = rsa_priv_cipher.decrypt(data).decode()
                    print(data)
            else:
                break
        else:
            data = sock.recv(2048).decode()

            if data:
                if data == "INVALID PASSWORD":
                    print("Invalid password , quitting")
                    quit()
                else:
                    print(data)
            else:
                break


threading.Thread(target=rec_messages, args=(sock,)).start()

while True:


    msg = input("> ")

    print("\r" , end="")
    sys.stdout.write("\033[F")
    if secure_mode:
        msg = f"{pass_hash}<|SEP|>{username}<|SEP|>{msg}"
        if server_side_encryption:
            msg = server_cipher_rsa.encrypt(msg.encode())
            sock.sendall(msg)
        else:
            sock.sendall(msg.encode())
    else:
        msg = f"{username}<|SEP|>{msg}"
        sock.sendall(msg.encode())





