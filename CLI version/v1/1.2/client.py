print("0xChat CLI Mode")
print("v1.2")
print("Made by 0xAppoloyon")
print("twitter.com/0xAppoloyon\n")

username = input("Enter your username to connect: ")
server = input("Enter server ip: ")
port = int(input("Enter port to connect: "))



import socket
import sys
import os
import threading

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
    
    print("\r" , end="")
    sys.stdout.write("\033[F")
    msg = f"{username}: {msg}"
    sock.sendall(msg.encode())


