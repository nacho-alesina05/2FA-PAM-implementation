#include <stdio.h>
#include <stdlib.h>
#include <qrencode.h>
#include <cotp.h>
#include <string.h>
#include "generate_seed.h"
#include "custom_base32_encode.h"
#include "obtain_totp.h"

#define COTP_SECRET_MAX_LEN 20
#define COTP_SECRET_BASE32_LEN 32
#define BASE32_SECRET_LEN 32

char *read_file(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        perror("Error al abrir el archivo");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char *content = malloc(file_size + 1); // +1 para el carácter nulo
    if (content == NULL) {
        perror("Error al asignar memoria");
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(content, 1, file_size, file);
    if (read_size != file_size) {
        perror("Error al leer el archivo");
        free(content);
        fclose(file);
        return NULL;
    }

    content[file_size] = '\0';
    fclose(file);

    // Eliminar el carácter de nueva línea si existe
    char *newline = strchr(content, '\n');
    if (newline) {
        *newline = '\0';
    }

    return content;
}

int main() {
    // Obtiene el directorio home del usuario actual
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
        fprintf(stderr, "Error al obtener el directorio home\n");
        return EXIT_FAILURE;
    }

    // Construye la ruta del archivo
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/2fa.txt", home_dir);

    // Verificar si el archivo ya existe
    FILE *file = fopen(file_path, "r");
    if (file != NULL) {
        printf("El archivo 2fa.txt ya existe en el directorio home. No se sobrescribirá.\n");
        fclose(file);
    } else {
        // Generar la semilla usando generate_seed
        unsigned char* secret = generate_seed();

        // Convertir la clave secreta a formato Base32
        char base32_secret[COTP_SECRET_BASE32_LEN + 1];  // +1 para el carácter nulo
        custom_base32_encode(secret, COTP_SECRET_MAX_LEN, base32_secret);
        printf("Base32 Secret: %s\n", base32_secret);

        // Abre el archivo en modo escritura, creándolo si no existe
        file = fopen(file_path, "w");
        if (file == NULL) {
            perror("Error al abrir el archivo");
            return EXIT_FAILURE;
        }

        // Escribe la semilla en el archivo
        fprintf(file, "%s\n", base32_secret);

        // Cierra el archivo
        fclose(file);

        // Cambia los permisos del archivo a r--------
        // if (chmod(file_path, S_IRUSR) != 0) {
        //     perror("Error al cambiar los permisos del archivo");
        //     return EXIT_FAILURE;
        // }

        // Generar el código QR con la URL de configuración de TOTP
        char url[256];
        snprintf(url, sizeof(url), "otpauth://totp/%s?secret=%s&issuer=%s", "user", base32_secret, "Example");
        QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        if (!qrcode) {
            fprintf(stderr, "Error generating QR code.\n");
            return 1;
        }

        // Imprimir el QR en ASCII
        for (int y = 0; y < qrcode->width; y++) {
            for (int x = 0; x < qrcode->width; x++) {
                printf(qrcode->data[y * qrcode->width + x] & 1 ? "██" : "  ");
            }
            printf("\n");
        }
        QRcode_free(qrcode);
        printf("\n");
    }

    // Usar la clave en formato Base32 para obtener el TOTP
    cotp_error_t error;
    char *totp = obtain_totp(read_file(file_path), &error);
    if (error) {
        fprintf(stderr, "Error obtaining TOTP: %d\n", error);
    } else {
        printf("TOTP: %s\n", totp);
        free(totp);
    }

    return 0;
}
