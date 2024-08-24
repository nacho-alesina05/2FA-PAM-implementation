#include "obtain_totp.h"

char *obtain_totp(unsigned char secret[COTP_SECRET_MAX_LEN], cotp_error_t *err) {
     return get_totp(secret, 6, 30, SHA1, err);
 }    