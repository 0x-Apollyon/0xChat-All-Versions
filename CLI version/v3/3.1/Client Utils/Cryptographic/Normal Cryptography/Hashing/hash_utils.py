import hashlib
from hashbase import RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320
from Crypto.Hash import keccak 
from Crypto.Hash import SHA512
import os
import hmac 
from argon2 import PasswordHasher
import secrets
import random
import gc

cwd = os.getcwd()

def startup_menu():
    os.system("cls")
    print("0xChat HASHING UTILS [Client Side]")
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

    print("1: Select an algorithm to hash text \n2: Select an algorithm to hash text alongside HMAC \n3: Purge available hashfiles \n4: Clear Screen")

startup_menu()

def save_menu(hash):
    save_option = input("Do you want to save the generated hash ? [y/N]: ").lower().strip()
    if save_option in ["y" , "yes"]:
        file_name = input("Enter file name to save [THE HASH WOULD BE STORED IN THE \Hashes\ DIRECTORY. IF THE FILE ALREADY EXISTS IT WOULD BE OVERWRITTEN]: ")
        file_path = os.path.join(cwd , "Hashes" , f"{file_name}.aplyn")
        f = open(file_path, 'w')
        f.write(hash)
        f.close()

def file_wiper(file_path):
    file_size = os.path.getsize(file_path)
    for i in range(random.randint(128,256)):
        gc.collect()
        overwriting_content = secrets.token_bytes(file_size)
        f = open(file_path , "wb")
        f.write(overwriting_content)
        f.close()
        del f
    os.remove(file_path)

while True:
    option = input("Enter your option: ")
    if option == "1":
        print(""" --AVAILABLE HASHING ALGORITHMS--

--> SHA-2 [1]
    -> SHA-224 [1A]
    -> SHA-256 [1B]
    -> SHA-384 [1C]
    -> SHA-512 [1D]
    -> SHA-512/224 [1E]
    -> SHA-512/256 [1F]

--> SHA-3 [2]
    -> SHA3-224 [2A]
    -> SHA3-256 [2B]
    -> SHA3-384 [2C]
    -> SHA3-512 [2D]

--> RIPEMD [3]
    -> RIPEMD-128 [3A]
    -> RIPEMD-160 [3B]
    -> RIPEMD-256 [3C]
    -> RIPEMD-320 [3D]

--> KECCAK [4]
    -> KECCAK-224 [4A]
    -> KECCAK-256 [4B]
    -> KECCAK-384 [4C]
    -> KECCAK-512 [4D]
                 
--> SHAKE [5]
    -> SHAKE-128 [5A]
    -> SHAKE-256 [5B]

--> BLAKE [6]
    -> BLAKE-2b [6A]
    -> BLAKE-2s [6B]

--> MISC [7A]
    -> ARGON-2 [7A] (WARNING: SLOW AND RESOURCE INTENSIVE)
    -> MD-5 [7B] (WARNING: VULNERABLE TO COLLISIONS AND UNSECURE)
    -> SHA-1 [7C] (WARNING: VULNERABLE TO COLLISIONS AND UNSECURE)

    """)
        
        

        hashing_algorithm = input("Enter the hashing algorithm to use (NAME OR CODE): ").lower().strip()
        
        if hashing_algorithm in ["sha224" , "sha-224" , "1a" , "[1a]" , "sha 224"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha224(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha256" , "sha-256" , "1b" , "[1b]" , "sha 256"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha256(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha384" , "sha-384" , "1c" , "[1c]" , "sha 384"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha384(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha512" , "sha-512" , "1d" , "[1d]" , "sha 512"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha512(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha512224" , "sha-512-224" , "1e" , "[1e]" , "sha 512 224" , "sha-512/224" , "sha-512224"]:
            text = input("Enter the text you want to hash: ")
            h = SHA512.new(truncate="224")
            h.update(text.encode())
            hash_gen = h.hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha512256" , "sha-512-256" , "1f" , "[1f]" , "sha 512 256" , "sha-512/256" , "sha-512256"]:
            text = input("Enter the text you want to hash: ")
            h = SHA512.new(truncate="256")
            h.update(text.encode())
            hash_gen = h.hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha3224" , "sha3-224" , "2a" , "[2a]" , "sha-3-224" , "sha 3 224" , "sha-3 224"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha3_224(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha3256" , "sha3-256" , "2b" , "[2b]" , "sha-3-256" , "sha 3 256" , "sha-3 256"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha3_256(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha3384" , "sha3-384" , "2c" , "[2c]" , "sha-3-384" , "sha 3 384" , "sha-3 384"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha3_384(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha3512" , "sha3-512" , "2d" , "[2d]" , "sha-3-512" , "sha 3 512" , "sha-3 512"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha3_512(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["ripemd128" , "ripemd-128" , "3a" , "[3a]" , "ripemd 128"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = RIPEMD128().generate_hash(text)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["ripemd160" , "ripemd-160" , "3b" , "[3b]" , "ripemd 160"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = RIPEMD160().generate_hash(text)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["ripemd256" , "ripemd-256" , "3c" , "[3c]" , "ripemd 256"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = RIPEMD256().generate_hash(text)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["ripemd320" , "ripemd-320" , "3d" , "[3d]" , "ripemd 320"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = RIPEMD320().generate_hash(text)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["keccak224" , "keccak-224" , "4a" , "[4a]" , "keccak 224"]:
            text = input("Enter the text you want to hash: ")
            keccak_hash = keccak.new(digest_bits=224)
            keccak_hash.update(text.encode())
            hash_gen = keccak_hash.hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["keccak256" , "keccak-256" , "4b" , "[4b]" , "keccak 256"]:
            text = input("Enter the text you want to hash: ")
            keccak_hash = keccak.new(digest_bits=256)
            keccak_hash.update(text.encode())
            hash_gen = keccak_hash.hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["keccak384" , "keccak-384" , "4c" , "[4c]" , "keccak 384"]:
            text = input("Enter the text you want to hash: ")
            keccak_hash = keccak.new(digest_bits=384)
            keccak_hash.update(text.encode())
            hash_gen = keccak_hash.hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["keccak512" , "keccak-512" , "4d" , "[4d]" , "keccak 512"]:
            text = input("Enter the text you want to hash: ")
            keccak_hash = keccak.new(digest_bits=512)
            keccak_hash.update(text.encode())
            hash_gen = keccak_hash.hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["shake128" , "shake 128" , "5a" , "[5a]" , "shake-128"]:
            text = input("Enter the text you want to hash: ")
            length = int(input("Enter the length of the digest: "))
            hash_gen = hashlib.shake_128(text.encode()).hexdigest(length)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["shake256" , "shake 256" , "5b" , "[5b]" , "shake-256"]:
            text = input("Enter the text you want to hash: ")
            length = int(input("Enter the length of the digest: "))
            hash_gen = hashlib.shake_256(text.encode()).hexdigest(length)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["blake2b" , "blake 2b" , "6a" , "[6a]" , "blake-2-b" , "blake-2b"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.blake2b(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["blake2s" , "blake 2s" , "6b" , "[6b]" , "blake-2-s" , "blake-2s"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.blake2s(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["argon2" , "argon 2" , "7a" , "[7a]" , "argon-2"]:
            text = input("Enter the text you want to hash: ")
            ph = PasswordHasher()
            hash_gen = ph.hash(text)
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["md-5" , "md 5" , "7b" , "[7b]" , "md5"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.md5(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha-1" , "sha1" , "7c" , "[7c]" , "sha 1"]:
            text = input("Enter the text you want to hash: ")
            hash_gen = hashlib.sha1(text.encode()).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        else:
            print("[X] ALGORITHM NOT FOUND")
        

    elif option == "2":
        print(""" --AVAILABLE HMAC ALGORITHMS--

--> SHA-2 [1]
    -> SHA-224 [1A]
    -> SHA-256 [1B]
    -> SHA-384 [1C]
    -> SHA-512 [1D]

--> SHA-3 [2]
    -> SHA3-224 [2A]
    -> SHA3-256 [2B]
    -> SHA3-384 [2C]
    -> SHA3-512 [2D]

--> RIPEMD [3]
    -> RIPEMD-160 [3A]

--> MISC [4]
    -> MD-5 [4A] (WARNING: VULNERABLE TO COLLISIONS AND UNSECURE)
    -> SHA-1 [4B] (WARNING: VULNERABLE TO COLLISIONS AND UNSECURE)

    """)

        hmac_algorithm = input("Enter the hmac algorithm to use (NAME OR CODE): ").lower().strip()

        if hmac_algorithm in ["sha224" , "sha-224" , "1a" , "[1a]" , "sha 224"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha224).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha256" , "sha-256" , "1b" , "[1b]" , "sha 256"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha256).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha384" , "sha-384" , "1c" , "[1c]" , "sha 384"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha384).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha512" , "sha-512" , "1d" , "[1d]" , "sha 512"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha512).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha3224" , "sha3-224" , "2a" , "[2a]" , "sha-3-224" , "sha 3 224" , "sha-3 224"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha3_224).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha3256" , "sha3-256" , "2b" , "[2b]" , "sha-3-256" , "sha 3 256" , "sha-3 256"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha3_256).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha3384" , "sha3-384" , "2c" , "[2c]" , "sha-3-384" , "sha 3 384" , "sha-3 384"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha3_384).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["sha3512" , "sha3-512" , "2d" , "[2d]" , "sha-3-512" , "sha 3 512" , "sha-3 512"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha3_512).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hmac_algorithm in ["ripemd160" , "ripemd-160" , "3a" , "[3a]" , "ripemd 160" , "3" , "3a"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.ripemd160).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["md-5" , "md 5" , "4a" , "[4a]" , "md5"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.md5).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        elif hashing_algorithm in ["sha-1" , "sha1" , "4b" , "[4b]" , "sha 1"]:
            text = input("Enter the text you want to hmac: ")
            hmac_string = input("Enter the hmac key: ")
            hash_gen = hmac.new(hmac_string.encode(), text.encode(), hashlib.sha1).hexdigest()
            print(hash_gen)
            save_menu(hash_gen)
        else:
            print("[X] ALGORITHM NOT FOUND FOR HMAC")
    
    elif option == "3":
        hashes_path = os.path.join(cwd , "Hashes")
        for file in os.listdir(hashes_path):
            file_complete_path = os.path.join(hashes_path , file)
            if os.path.isfile(file_complete_path):
                file_wiper(file_complete_path)
            else:
                continue
        else:
            print("[!] PURGED ALL HASH FILES")
            print("[!] CLEARING CONSOLE OUTPUT")
            gc.collect()
            startup_menu()

    elif option == "4":
        startup_menu()

    else:
        print("[X] INVALID OPTION")

    
    
        