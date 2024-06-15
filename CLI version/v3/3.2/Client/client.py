print("0xChat CLI Mode")
print("v3.2")
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
import ctypes 
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256


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
            
            password = pwinput.pwinput(prompt="Enter your password (required to connect to secure servers): ", mask='*')

            salts_json_file = os.path.join(cwd , "Client Utils" , "salts.json")
            f = open(salts_json_file , "r")
            salts_file = f.read()
            f.close()
            salts_file = json.loads(salts_file)
            json_key = username + ";" + server + ";" + str(port)
            if json_key in salts_file:
                salt = salts_file[json_key]
                password = password + salt
                password = password.encode()
                password_client_hash = hashlib.sha3_512(password) 
                client_access_password = password_client_hash.hexdigest()
                print(client_access_password)
            else:
                salt = os.urandom(32).decode('latin1')
                password = password + salt
                password = password.encode()
                password_client_hash = hashlib.sha3_512(password) 
                client_access_password = password_client_hash.hexdigest()
                salts_file[json_key] = salt
                salts_file = json.dumps(salts_file)
                f = open(salts_json_file , "w")
                f.write(salts_file)
                f.close()



else:
    
    username = input("Enter your username to connect: ")
    server = input("Enter server ip: ")
    port = int(input("Enter port to connect: "))
    password = pwinput.pwinput(prompt="Enter your password (required to connect to secure servers): ", mask='*')
    to_save = input("Want to save this server to the fast connect list [y/N]: ")


    

    salts_json_file = os.path.join(cwd , "Client Utils" , "salts.json")
    f = open(salts_json_file , "r")
    salts_file = f.read()
    f.close()
    salts_file = json.loads(salts_file)
    json_key = username + ";" + server + ";" + str(port)
    if json_key in salts_file:
        salt = salts_file[json_key]
        password = password + salt
        password = password.encode()
        password_client_hash = hashlib.sha3_512(password) 
        client_access_password = password_client_hash.hexdigest()
    else:
        salt = os.urandom(32).decode('latin1')
        password = password + salt
        password = password.encode()
        password_client_hash = hashlib.sha3_512(password) 
        client_access_password = password_client_hash.hexdigest()
        salts_file[json_key] = salt
        salts_file = json.dumps(salts_file)
        f = open(salts_json_file , "w")
        f.write(salts_file)
        f.close()


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


if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")



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
password_hashing_scheme = init_data[4]
if init_data[2] == "SYM-ENCRYPTION:ENABLED":
    server_side_encryption = True
    cryptography_path = os.path.join(client_utils_path , "Cryptographic") 
    pre_quantum = os.path.join(cryptography_path, "Normal Cryptography")
    normal_cryptography_keys_asym_path = os.path.join(pre_quantum , "Assymetric" , "Keys")
    rsa_public_key_path = os.path.join(normal_cryptography_keys_asym_path , "rsa_public_key.aplyn")
    rsa_private_key_path = os.path.join(normal_cryptography_keys_asym_path , "rsa_private_key.aplyn")

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

    session_id = sock.recv(2048)
    nonce = sock.recv(2048)
    session_id = rsa_priv_cipher.decrypt(session_id)
    nonce = rsa_priv_cipher.decrypt(nonce)
    

if secure_mode.lower() == "securemode:enabled":
    secure_mode = True
    password_hashing_scheme = password_hashing_scheme.split(":")[1]
    password = client_access_password.encode()
    if password_hashing_scheme == "sha_224":
        pass_hash = hashlib.sha224(password) 
        pass_hash = pass_hash.hexdigest()
    elif password_hashing_scheme == "sha_256":
        pass_hash = hashlib.sha256(password)
        pass_hash = pass_hash.hexdigest()
    elif password_hashing_scheme == "sha_384":
        pass_hash = hashlib.sha384(password)
        pass_hash = pass_hash.hexdigest()
    elif password_hashing_scheme == "sha_512":
        pass_hash = hashlib.sha512(password)
        pass_hash = pass_hash.hexdigest()

    elif password_hashing_scheme == "sha3_224":
        pass_hash = hashlib.sha3_224(password) 
        pass_hash = pass_hash.hexdigest()
    elif password_hashing_scheme == "sha3_256":
        pass_hash = hashlib.sha3_256(password)
        pass_hash = pass_hash.hexdigest()
    elif password_hashing_scheme == "sha3_384":
        pass_hash = hashlib.sha3_384(password)
        pass_hash = pass_hash.hexdigest()
    elif password_hashing_scheme == "sha3_512":
        pass_hash = hashlib.sha3_512(password)
        pass_hash = pass_hash.hexdigest()
        print(pass_hash)
    
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
                    session_cipher = AES.new(session_id, AES.MODE_EAX , nonce=nonce)
                    data = session_cipher.decrypt(data).decode()
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
        msg = {"password":pass_hash, "username":username, "msg":msg}
        msg = json.dumps(msg)
        if server_side_encryption:
            session_cipher = AES.new(session_id, AES.MODE_EAX , nonce=nonce)
            msg = session_cipher.encrypt(msg.encode())
            sock.sendall(msg)
        else:
            sock.sendall(msg.encode())
    else:
        msg = {"username":username, "msg":msg}
        msg = json.dumps(msg)
        sock.sendall(msg.encode())





