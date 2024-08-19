#include <stdio.h>
#include <stdlib.h>
#include <qrencode.h>
#include <cotp.h>
#include <string.h>
#include "sodium.h"
#include "generate_seed.h"
#include "custom_base32_encode.h"
#include "obtain_totp.h"

#define COTP_SECRET_MAX_LEN 20
#define COTP_SECRET_BASE32_LEN 32
#define BASE32_SECRET_LEN 32

int main() {
    // Generar la semilla usando generate_seed
    // Se genera una clave secreta de 20 bytes de largo (COTP_SECRET_MAX_LEN).
    unsigned char* secret = generate_seed();

    // Convertir la clave secreta a formato Base32
    // La clave en formato binario se convierte a un string Base32 para su uso en el TOTP.
    char base32_secret[COTP_SECRET_BASE32_LEN + 1];  // +1 para el carácter nulo
    custom_base32_encode(secret, COTP_SECRET_MAX_LEN, base32_secret);
    printf("Base32 Secret: %s\n", base32_secret);

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
    char *totp = obtain_totp(base32_secret, &error);
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
