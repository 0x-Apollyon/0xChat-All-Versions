print("0xChat CLI Mode Server")
print("v1.2")
print("Made by 0xAppoloyon")
print("twitter.com/0xAppoloyon\n")

port = int(input("Enter port to run server on: "))
max_user_count = int(input("Enter max user count:"))


import socket
import os
import threading

os.system("cls")
hostname = socket.gethostname()
server = socket.gethostbyname(hostname)



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
                print(f"Message recieved --> {data}")
                broadcast_all(data)
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


    

            
