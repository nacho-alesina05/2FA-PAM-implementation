# 2FA-PAM-implementation

## Installation
The following libraries must be downloaded:
-libcotp

-qrencode

-libgcrypt

-libpam-dev

## For generating & installing the module: 
The ssh connection is hardcoded.

sh build.sh


#Comando para probar funcionalidades nuevas en el main.c:
gcc -I./include -o generate_qr main.c src/generate_seed.c src/custom_base32_encode.c src/obtain_totp.c -lcotp -lqrencode -lsodium -lssl -lcrypto -lgcrypt
./generate_qr