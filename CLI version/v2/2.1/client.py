print("0xChat CLI Mode")
print("v2.1")
print("Made by 0xAppoloyon")
print("twitter.com/0xAppoloyon\n")

username = input("Enter your username to connect: ")
server = input("Enter server ip: ")
port = int(input("Enter port to connect: "))
password = input("Enter your password (required to connect to secure servers)")


import socket
import hashlib 
import sys
import os
import threading

os.system("cls")

pass_hash = hashlib.sha256(password.encode()) 
pass_hash = pass_hash.hexdigest()

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
    msg = f"{pass_hash}<|SEP|>{username}<|SEP|>{msg}"
    sock.sendall(msg.encode())




