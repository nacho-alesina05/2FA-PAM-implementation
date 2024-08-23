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
    // Generar la semilla usando generate_seed
    // Se genera una clave secreta de 20 bytes de largo (COTP_SECRET_MAX_LEN).
    unsigned char* secret = generate_seed();

    // Convertir la clave secreta a formato Base32
    // La clave en formato binario se convierte a un string Base32 para su uso en el TOTP.
    char base32_secret[COTP_SECRET_BASE32_LEN + 1];  // +1 para el carácter nulo
    custom_base32_encode(secret, COTP_SECRET_MAX_LEN, base32_secret);
    printf("Base32 Secret: %s\n", base32_secret);

    // Almacenar seed en lugar seguro

    // Obtiene el directorio home del usuario actual
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
        fprintf(stderr, "Error al obtener el directorio home\n");
        return EXIT_FAILURE;
    }

    // Construye la ruta del archivo
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/2fa.txt", home_dir);

    // Abre el archivo en modo escritura, creándolo si no existe
    FILE *file = fopen(file_path, "w");
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
    // Se crea la URL para la configuración de TOTP en una aplicación como Google Authenticator.
    char url[256];
    snprintf(url, sizeof(url), "otpauth://totp/%s?secret=%s&issuer=%s", "user", base32_secret, "Example");
    QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qrcode) {
        fprintf(stderr, "Error generating QR code.\n");
        return 1;
    }

    // Imprimir el QR en ASCII
    // Se imprime el código QR en formato ASCII en la terminal.
    for (int y = 0; y < qrcode->width; y++) {
        for (int x = 0; x < qrcode->width; x++) {
            printf(qrcode->data[y * qrcode->width + x] & 1 ? "██" : "  ");
        }
        printf("\n");
    }
    QRcode_free(qrcode);
    printf("\n");

    // Usar la clave en formato Base32 para obtener el TOTP
    // Se genera el código TOTP basado en la clave secreta en Base32.
    cotp_error_t error;
    char *totp = obtain_totp(read_file(file_path), &error);
    if (error) {
        // Si ocurre un error durante la generación del TOTP, se imprime un mensaje de error.
        fprintf(stderr, "Error obtaining TOTP: %d\n", error);
    } else {
        // Si la generación del TOTP es exitosa, se imprime el código generado.
        printf("TOTP: %s\n", totp);
        free(totp);  // Liberar la memoria usada para almacenar el TOTP.
    }

    return 0;
}
