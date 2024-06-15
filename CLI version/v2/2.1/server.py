print("0xChat CLI Mode Server")
print("v2.1")
print("Made by 0xAppoloyon")
print("twitter.com/0xAppoloyon\n")

port = int(input("Enter port to run server on: "))
max_user_count = int(input("Enter max user count:"))
mode = input("Do you want to run in secure mode (password verification) [y/n]: ")




import socket
import os
import threading
import json

os.system("cls")
hostname = socket.gethostname()
server = socket.gethostbyname(hostname)
cwd = os.getcwd()

server_utils_path = os.path.join(cwd , "Server Utils")

if mode.lower() == "y":
    pass_file_path = os.path.join(server_utils_path , "passwords.json")
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
    for client in client_list:
        client.sendall(data.encode())

def handle_client(conn , caddr):
    while True:
        try:
            data = conn.recv(2048).decode()

            if data:
                data_arr = data.split("<|SEP|>")
                password_hash = data_arr[0]
                username = data_arr[1]
                message = data_arr[2]

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
                conn.close()
                client_list.remove(conn)
                break

        except:
            pass
        

sock.listen(max_user_count)

while True:
    conn, caddr = sock.accept()
    print(f"New client connection: {caddr}")
    client_list.append(conn)
    threading.Thread(target=handle_client, args=(conn , caddr,)).start()


    

            
