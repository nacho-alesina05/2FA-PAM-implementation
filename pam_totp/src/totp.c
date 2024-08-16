#include "totp.h"
#include <stdio.h>
#include <string.h>

// Genera el URL para configurar TOTP en Google Authenticator.
void generate_totp_url(char *base32_encoded_seed, char *username, char *issuer, char *url) {
    sprintf(url, "otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, username, base32_encoded_seed, issuer);
}
