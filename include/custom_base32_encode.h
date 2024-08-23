#ifndef CUSTOM_BASE32_ENCODE_H
#define CUSTOM_BASE32_ENCODE_H
#include <stdio.h>
#include <stdlib.h>
#include <cotp.h>
#include <string.h>
#include "generate_seed.h"
#include "custom_base32_encode.h"

void custom_base32_encode(const unsigned char *input, size_t input_length, char *output);

#endif // CUSTOM_BASE32_ENCODE_H