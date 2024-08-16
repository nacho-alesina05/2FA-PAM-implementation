#include "base32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Implementa la conversión a Base32 aquí.
// Puedes usar una librería existente o crear tu propia función.
void convert_to_base32(unsigned char *seed, char *base32_encoded_seed, size_t seed_len) {
    int i, index = 0, bit_count = 0;
    unsigned int buffer = 0;

    for (i = 0; i < seed_len; i++) {
        buffer <<= 8;
        buffer |= seed[i] & 0xFF;
        bit_count += 8;

        while (bit_count >= 5) {
            base32_encoded_seed[index++] = base32_chars[(buffer >> (bit_count - 5)) & 0x1F];
            bit_count -= 5;
        }
    }

    if (bit_count > 0) {
        base32_encoded_seed[index++] = base32_chars[(buffer << (5 - bit_count)) & 0x1F];
    }

    // Padding with '=' as per Base32 standard if needed
    while (index % 8 != 0) {
        base32_encoded_seed[index++] = '=';
    }

    base32_encoded_seed[index] = '\0'; // Null-terminate the encoded string
}
