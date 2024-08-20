# 2FA-PAM-implementation

se tiene q instalar la libreria qrencode y libcotp
sudo apt-get install libqrencode-dev && libcotp-dev 
para tener libgcrypt
sudo apt-get install libgcrypt20-dev

#Comando para ejecutar el programa: 

gcc -I./include -o generate_qr main.c src/custom_base32_encode.c src/generate_seed.c src/obtain_totp.c -lcrypt -lcotp -lgcrypt -lqrencode

./generate_qr