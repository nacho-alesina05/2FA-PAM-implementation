#!/bin/bash

# Limpiar la compilación anterior
make clean

# Compilar el proyecto
make

# Generar el código QR
./generate_qr

# Conectar a través de SSH
ssh rodri@127.0.0.1
