#ifndef TOTP_H
#define TOTP_H

void generate_totp_url(char *base32_encoded_seed, char *username, char *issuer, char *url);

#endif // TOTP_H
