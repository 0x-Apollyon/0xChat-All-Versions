print("0xChat CLI Mode")
print("v2.2")
print("Made by 0xAppoloyon")
print("twitter.com/0xAppoloyon\n")

import socket
import hashlib 
import sys
import os
import threading
import json

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

        print(saved_server_list)
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
if secure_mode.lower() == "securemode:enabled":
    secure_mode = True
else:
    secure_mode = False



def rec_messages(sock):
    while True:
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
    else:
        msg = f"{username}<|SEP|>{msg}"

    sock.sendall(msg.encode())





