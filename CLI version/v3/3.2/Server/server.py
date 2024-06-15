print("0xChat CLI Mode Server")
print("v3.2")
print("Made by 0xApollyon")
print("twitter.com/0xApollyon\n")

import socket
import os
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pwinput
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256



cwd = os.getcwd()

global passwords

server_utils_path = os.path.join(cwd , "Server Utils")

config_set = input("Do you want to auto-load the config file [y/n]: ")

if config_set.lower() == "y":

    config_file_path = os.path.join(server_utils_path , "config.json")
    f = open(config_file_path, "r")
    configurations = f.read()
    f.close()

    configurations = json.loads(configurations)
    port = configurations["default-port"]
    max_user_count = configurations["default-max-clients"]
    mode = configurations["secure-mode"]
    sym_encryption = configurations["client-server-encryption"]
    encryption_algo = configurations["encryption-algo"]
    hashing_scheme = configurations["hashing-algo"]

    if sym_encryption == "true":
        sym_encryption = True
    else:
        sym_encryption = False

    if mode == "false":
        mode = "n"
    else:
        mode = "y"

else:
    port = int(input("Enter port to run server on: "))
    max_user_count = int(input("Enter max user count:"))
    mode = input("Do you want to run in secure mode (password verification) [y/n]: ").lower()
    sym_encryption = input("Do you want symmetric encryption [y/n]: ").lower()
    if sym_encryption == "y":
        sym_encryption = True
    elif sym_encryption == "f":
        sym_encryption = False
    else:
        print("[!] INVALID OPTION FOR SYM ENCRYPTION")
        quit()
    encryption_algo = "RSA"    
    hashing_scheme = input("Enter the hashing sceme you want to use: ").lower()
    if hashing_scheme not in ["sha_224" , "sha_256" , "sha_384" , "sha_512" , "sha3_224" , "sha3_256" , "sha3_384" , "sha3_512"]:
        print("[!] INVALID HASHING SCHEME")
        quit()

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")
hostname = socket.gethostname()
server = socket.gethostbyname(hostname)

if mode.lower() == "y":
    password_db_path = os.path.join(server_utils_path , "Password DB")
    pass_file_path = os.path.join(password_db_path , "passwords.json")
    f = open(pass_file_path, "r")
    passwords = f.read()
    f.close()

    passwords = json.loads(passwords)




print(r"""
_______         _________ .__            __   
\   _  \ ___  __\_   ___ \|  |__ _____ _/  |_ 
/  /_\  \\  \/  /    \  \/|  |  \\__  \\   __\
\  \_/   \>    <\     \___|   Y  \/ __ \|  |  
 \_____  /__/\_ \\______  /___|  (____  /__|  
       \/      \/       \/     \/     \/      

""")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind((server, port))
print(f"Running on {server}:{port}")


global client_list
client_list = []
def broadcast_all(data):
    global client_list
    if sym_encryption:
        for client in client_list:
            client_ip = client[0]
            client_cipher_rsa = client[1]
            session_id = client[2]
            nonce = client[3]

            session_cipher = AES.new(session_id, AES.MODE_EAX , nonce=nonce)
            
            enc_msg = session_cipher.encrypt(data.encode())
            client_ip.sendall(enc_msg)
    else:
        for client in client_list:
            client.sendall(data.encode())

def handle_client(conn , caddr , session_id , nonce):
    while True:
        try:
            if sym_encryption:
                data = conn.recv(2048)
                if data:
                    session_cipher = AES.new(session_id, AES.MODE_EAX , nonce=nonce)
                    data = session_cipher.decrypt(data).decode()
                    if mode == "y":
                        data_arr = json.loads(data)
                        password_hash = data_arr["password"]
                        username = data_arr["username"]
                        message = data_arr["msg"]
                        
                        if passwords[username]  == password_hash:
                                print(f"Message recieved --> {username}:{message}")
                                broadcast_all(f"{username}:{message}")
                        else:
                            conn.sendall(b"INVALID PASSWORD")
                            print(f"[!] {caddr} connected as {username} with an invalid password")
                            conn.close()
                            client_list.remove(conn)
                            break
                    else:
                        data_arr = json.loads(data)
                        username = data_arr["username"]
                        message = data_arr["msg"]

                        print(f"Message recieved --> {username}:{message}")
                        broadcast_all(f"{username}:{message}")
                else:
                    print(f"Client disconnected: {caddr}")
                    conn.close()
                    client_list.remove(conn)
                    break
            else:
                data = conn.recv(2048).decode()

                if data:
                    if mode == "y":
                        data_arr = json.loads(data)
                        password_hash = data_arr["password"]
                        username = data_arr["username"]
                        message = data_arr["msg"]

                        if passwords[username]  == password_hash:
                                print(f"Message recieved --> {username}:{message}")
                                broadcast_all(f"{username}:{message}")
                        else:
                            conn.sendall(b"INVALID PASSWORD")
                            print(f"[!] {caddr} connected as {username} with an invalid password")
                            conn.close()
                            client_list.remove(conn)
                            break
                    else:
                        data_arr = json.loads(data)
                        username = data_arr["username"]
                        message = data_arr["msg"]

                        print(f"Message recieved --> {username}:{message}")
                        broadcast_all(f"{username}:{message}")
                else:
                    print(f"Client disconnected: {caddr}")
                    conn.close()
                    client_list.remove(conn)
                    break

        except Exception as error:
            if error == "[WinError 10054] An existing connection was forcibly closed by the remote host":
                print(f"Client disconnected: {caddr}")
                conn.close()
                client_list.remove(conn)
                break
            else:
                pass
        

sock.listen(max_user_count)
if mode == "y":
    sc_mode = "ENABLED"
else:
    sc_mode = "DISABLED"
if sym_encryption:
    sm_enc = "ENABLED"

    if encryption_algo.lower() == "rsa":
        cryptography_path = os.path.join(server_utils_path , "Cryptographic")
        pre_quantum_path = os.path.join(cryptography_path , "Normal Cryptography" , "Asymmetric" , "Keys")
        rsa_public_key_path = os.path.join(pre_quantum_path   , "rsa_public_key.aplyn")
        rsa_private_key_path = os.path.join(pre_quantum_path  , "rsa_private_key.aplyn")

        if os.path.isfile(rsa_public_key_path):
            f = open(rsa_public_key_path , "r")
            rsa_public_key = f.read()
            f.close()
            if rsa_public_key == "":
                print("[!] NO PUBLIC KEY FOUND, PLEASE GENERATE ONE USING SERVER TOOLS")
                quit()
            else:
                with open(rsa_public_key_path, "rt") as f:
                    rsa_public_key_raw = f.read()
                    rsa_public_key = RSA.import_key(rsa_public_key_raw)
        else:
            print("[!] NO PUBLIC KEY FOUND, PLEASE GENERATE ONE USING SERVER TOOLS")
            quit()

        if os.path.isfile(rsa_private_key_path):
            f = open(rsa_private_key_path , "r")
            rsa_private_key = f.read()
            f.close()

            if rsa_private_key == "":
                print("[!] NO PRIVATE KEY FOUND, PLEASE GENERATE ONE USING SERVER TOOLS")
                quit()
            else:
                password = pwinput.pwinput(prompt='Enter password to access the key: ', mask='*')
                password = password.encode()
                try:
                    with open(rsa_private_key_path, "rb") as f:
                        key_data = f.read()
                        rsa_priv_key = RSA.import_key(key_data, passphrase=password)
                        rsa_priv_cipher = PKCS1_OAEP.new(rsa_priv_key)
                        print("RSA KEY LOADED. SERVER READY")

                except:
                    print("[!] ERROR IMPORTING PRIVATE KEY, CHECK IF YOUR PASSWORD IS CORRECT")
                    quit()
        else:
            print("[!] NO PRIVATE KEY FOUND, PLEASE GENERATE ONE USING SERVER TOOLS")
            quit()


        

else:
    sm_enc = "DISABLED"

server_info_msg = f"--SERVER-INFO--|SECUREMODE:{sc_mode}|SYM-ENCRYPTION:{sm_enc}|RSA-KEY:{rsa_public_key_raw}|HASHING-SCHEME:{hashing_scheme}"

while True:
    if not sym_encryption:
        conn, caddr = sock.accept()
        print(f"New client connection: {caddr}")
        conn.sendall(server_info_msg.encode())
        client_list.append(conn)
        threading.Thread(target=handle_client, args=(conn , caddr,)).start()
    else:
        conn, caddr = sock.accept()
        print(f"New client connection: {caddr}")
        conn.sendall(server_info_msg.encode())
        data = conn.recv(2048).decode()
        if data:
            data = data.split("|")
            client_rsa_key = data[1]
            client_public_key = RSA.import_key(client_rsa_key)
            client_cipher_rsa = PKCS1_OAEP.new(client_public_key)
            server_session_id = os.urandom(32)
            session_cipher = AES.new(server_session_id, AES.MODE_EAX)
            nonce = session_cipher.nonce
            enc_msg = client_cipher_rsa.encrypt(server_session_id)
            conn.sendall(enc_msg)
            enc_nonce = client_cipher_rsa.encrypt(nonce)
            conn.sendall(enc_nonce)
            client_list.append((conn,client_cipher_rsa , server_session_id , nonce))
            threading.Thread(target=handle_client, args=(conn , caddr, server_session_id , nonce,)).start()


    

            
