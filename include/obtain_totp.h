#ifndef OBTAIN_TOTP_H
#define OBTAIN_TOTP_H

#include <stdio.h>
#include <stdlib.h>
#include <cotp.h>
#include <string.h>
#include "sodium.h"
#include "generate_seed.h"
#include "custom_base32_encode.h"
#define COTP_SECRET_MAX_LEN 20


char *obtain_totp(unsigned char secret[COTP_SECRET_MAX_LEN], cotp_error_t *err);

#endif // OBTAIN_TOTP_H