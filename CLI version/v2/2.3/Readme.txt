v2.3 !!!!
Release date - 27/3/24 (Two releases on same date ooh ma god)

Features added: 
--> Added ECC client tools [ECC:Eliptic Curve Cryptography]
--> Added ECC server tools 
--> Added RSA client tools 
--> Added RSA server tools
--> Implemented server side encryption using RSA

Dev Notes:
Using RSA right now, not suitable for large messages, plan to switch to RSA-AES pair.
Pycryptodome does not support ECC as of now, looking for a suitable library to implement ECC-AES aswell.
Added tools for ECC right now so when a sutiable library is found it can be implemented quickly.
Looking into post quantum cryptography aswell, CRYSTAL KYBER to be exact, might implement it aswell.

