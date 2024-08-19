#include "custom_base32_encode.h"

const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Function to encode the seed in Base32
void custom_base32_encode(const unsigned char *input, size_t input_length, char *output) {
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

    // No padding with '='
    output[j] = '\0';
}