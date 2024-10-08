# Definir variables
SRC_DIR = src
INCLUDE_DIR = include
LIB_PATH = /lib/x86_64-linux-gnu/security/
MAN_DIR = /usr/share/man/man1/
SOURCE_FILE = $(SRC_DIR)/pam_2fa.c
OBJECT_FILE = pam_2fa.o
SHARED_LIB = pam_2fa.so
QR_GENERATOR = generate_qr
MANUAL_FILE = tsi05.1

# Archivos fuente adicionales para generar el QR
QR_SOURCES = main.c $(SRC_DIR)/generate_seed.c $(SRC_DIR)/custom_base32_encode.c $(SRC_DIR)/obtain_totp.c $(SRC_DIR)/cypher.c
QR_FLAGS = -I$(INCLUDE_DIR) -lcotp -lqrencode -lcrypto -lgcrypt -lpam -lpam_misc

# Objetivo por defecto
all: $(QR_GENERATOR) $(OBJECT_FILE) $(SHARED_LIB) install

# Regla para compilar y generar el ejecutable QR
$(QR_GENERATOR): $(QR_SOURCES)
	@gcc $(QR_SOURCES) $(QR_FLAGS) -o $@
	@echo "Generado $@"

# Compilar el archivo fuente a objeto
$(OBJECT_FILE): $(SOURCE_FILE)
	@gcc -fPIC -c $< -o $@
	@echo "Compilado $< a $@"

# Crear la biblioteca compartida
$(SHARED_LIB): $(OBJECT_FILE)
	@gcc -shared -o $@ $< -lpam -lcotp -lcrypt -lgcrypt
	@echo "Creada la biblioteca compartida $@"

# Mover la biblioteca compartida a la carpeta de seguridad de PAM
install: $(QR_GENERATOR) $(OBJECT_FILE) $(SHARED_LIB)
	@echo "Moviendo $(SHARED_LIB) a $(LIB_PATH)..."
	@sudo mv $(SHARED_LIB) $(LIB_PATH)
	@sudo cp $(MANUAL_FILE) $(MAN_DIR)  # Copiar la página de manual
	@sudo mandb  # Actualizar la base de datos de manuales
	@sudo systemctl restart sshd
	@echo "Proceso completado."
	@sudo systemctl restart sshd
	@echo "Proceso completado."

# Limpiar archivos generados
clean:
	@rm -f $(QR_GENERATOR) $(OBJECT_FILE) $(SHARED_LIB)
	@echo "Archivos limpiados."

.PHONY: clean install all
