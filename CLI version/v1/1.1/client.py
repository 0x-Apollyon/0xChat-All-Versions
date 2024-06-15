import socket
import sys
import os
import threading

print("0xChat CLI Mode")
print("v1.1")
print("Made by 0xAppoloyon")
print("twitter.com/0xAppoloyon")

print(r"""
_______         _________ .__            __   
\   _  \ ___  __\_   ___ \|  |__ _____ _/  |_ 
/  /_\  \\  \/  /    \  \/|  |  \\__  \\   __\
\  \_/   \>    <\     \___|   Y  \/ __ \|  |  
 \_____  /__/\_ \\______  /___|  (____  /__|  
       \/      \/       \/     \/     \/      

""")

username = input("Enter your username to connect: ")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server = "127.0.0.1"
port = 100

sock.connect((server, port))
print("Connected" + server + " on port " + str(port) + "\n")

def rec_messages(sock):
    while True:
        data = sock.recv(2048).decode()
        

        if data:
            print(data)
        else:
            break


threading.Thread(target=rec_messages, args=(sock,)).start()

while True:

    msg = input("> ")
    msg = f"{username}: {msg}"
    sock.sendall(msg.encode())


