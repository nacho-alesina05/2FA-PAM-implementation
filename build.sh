#!/bin/bash

# Definir nombres de archivos
SOURCE_FILE="src/pam_test.c"
OBJECT_FILE="pam_test.o"
SHARED_LIB="pam_test.so"
LIB_PATH="/lib/x86_64-linux-gnu/security/"

# Compilar el archivo fuente a objeto
echo "Compilando $SOURCE_FILE a $OBJECT_FILE..."
gcc -fPIC -c $SOURCE_FILE -o $OBJECT_FILE

# Crear la biblioteca compartida
echo "Creando la biblioteca compartida $SHARED_LIB..."
gcc -shared -o $SHARED_LIB $OBJECT_FILE -lpam -lcotp -lcrypt -lgcrypt

# Mover la biblioteca compartida a la carpeta de seguridad de PAM
echo "Moviendo $SHARED_LIB a $LIB_PATH..."
sudo mv $SHARED_LIB $LIB_PATH

sudo systemctl restart sshd

# Paso 4: Probar la autenticación SSH
ssh rodri@127.0.0.1

echo "Proceso completado."

