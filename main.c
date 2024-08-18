// generate_qr.c
#include <stdio.h>
#include <stdlib.h>
#include <qrencode.h>
#include <cotp.h>
#include <string.h>
#include <openssl/rand.h>
#include "sodium.h"


#define COTP_SECRET_MAX_LEN 20
#define COTP_SECRET_BASE32_LEN 32
#define BASE32_SECRET_LEN 32

unsigned char* generate_seed() {
    // char key[32];
    static unsigned char key[COTP_SECRET_MAX_LEN];

    if (!key) {
        fprintf(stderr, "Error allocating memory for seed.\n");
        return NULL;
    }   
    randombytes_buf(key, sizeof(key));
    printf("key: ");
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return key;
    // return "JBSWY3DPEHPK3PXP";
}

const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void custom_base32_encode(const unsigned char *input, size_t input_length, char *output, size_t output_length) {
    size_t i, j;
    unsigned int buffer = 0;
    int bits_left = 0;
    
    for (i = 0, j = 0; i < input_length; ++i) {
        buffer <<= 8;
        buffer |= input[i];
        bits_left += 8;
        
        while (bits_left >= 5) {
            output[j++] = base32_alphabet[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }
    
    if (bits_left > 0) {
        output[j++] = base32_alphabet[(buffer << (5 - bits_left)) & 0x1F];
    }
    
    while (j < output_length) {
        output[j++] = '=';
    }
    
    output[output_length] = '\0';
}



char *obtain_totp(unsigned char secret[128], char *err){
    return get_totp(secret, 6, 30, 2, err);
}



int main() {
    // Generar la semilla usando generate_seed
    unsigned char* secret = generate_seed();
    // convert_to_hex(secret, hex_secret, 128);
    char *error;


    char base32_secret[COTP_SECRET_BASE32_LEN + 1];  // +1 for null terminator
    custom_base32_encode(secret, sizeof(secret), base32_secret, BASE32_SECRET_LEN);
    printf("Base32 Secret: %s\n", base32_secret);

    // Generar el QR
    char url[512];
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
    if (error) {
        fprintf(stderr, "Error obtaining TOTP: %s\n", error);
    } else {
        printf("TOTP: %s\n", totp);
        free(totp);
    }
    return 0;
}
