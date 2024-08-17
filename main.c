// generate_qr.c
#include <stdio.h>
#include <stdlib.h>
#include <qrencode.h>
#include <cotp.h>
#include <string.h>

#define COTP_SECRET_MAX_LEN 64
#define COTP_SECRET_BASE32_LEN 64

char *generate_seed(){
    return "JBSWY3DASHPK3PXP";
}

char *obtain_totp(char *secret, char *err){
    return get_totp(secret, 6, 30, 2, err);
}

//ver porque funciona sin estar en base32

int main() {
    // Generar la semilla usando libcotp
    char *secret = generate_seed();
    char *error;
/*
    // Codificar la semilla en Base32
    char base32_secret[COTP_SECRET_BASE32_LEN];
    cotp_base32_encode(secret, sizeof(secret), base32_secret, sizeof(base32_secret));

    // Construir el URL para otpauth
    char url[256];
    snprintf(url, sizeof(url), "otpauth://totp/%s?secret=%s&issuer=%s", "user", secret, "Example");
*/
    // Generar el QR
    char url[256];
    snprintf(url, sizeof(url), "otpauth://totp/%s?secret=%s&issuer=%s", "user", secret, "Example");
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

    char *totp = obtain_totp(secret, error);
    printf("TOTP: %s\n", totp);
    return 0;
}
