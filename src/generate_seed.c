#include "generate_seed.h"
#define COTP_SECRET_MAX_LEN 20

unsigned char* generate_seed() {
    static unsigned char key[COTP_SECRET_MAX_LEN];
    randombytes_buf(key, sizeof(key));

    printf("key: ");
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return key;
}