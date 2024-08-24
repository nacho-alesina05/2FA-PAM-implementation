#!/bin/bash

# Paso 1: Compilar todos los archivos fuente
gcc -I./include -fPIC -c main.c -o main.o
gcc -I./include -fPIC -c src/pam_test.c -o pam_test.o
gcc -I./include -fPIC -c src/obtain_totp.c -o obtain_totp.o
gcc -I./include -fPIC -c src/custom_base32_encode.c -o custom_base32_encode.o
gcc -I./include -fPIC -c src/generate_seed.c -o generate_seed.o

# Paso 2: Crear el ejecutable principal
gcc -o generate_qr main.o obtain_totp.o custom_base32_encode.o generate_seed.o -lcrypt -lcotp -lgcrypt -lqrencode

# Paso 3: Crear el módulo PAM compartido
gcc -shared -o pam_test.so pam_test.o -lpam

# Paso 4: Mover el módulo PAM a la carpeta de seguridad
sudo mv pam_test.so /lib/x86_64-linux-gnu/security/
 
# Paso 5: Reiniciar el servicio SSH para aplicar los cambios
sudo systemctl restart sshd

# Paso 6: Probar la autenticación SSH
ssh rodri@127.0.0.1

