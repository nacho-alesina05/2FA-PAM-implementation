#include "generate_seed.h"
#define COTP_SECRET_MAX_LEN 20

unsigned char* generate_seed() {
    static unsigned char key[COTP_SECRET_MAX_LEN];

    // Inicializar la biblioteca Gcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        return NULL;
    }

    // Asegurarse de que los registros de seguridad se gestionen correctamente
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Generar la semilla de forma segura
    gcry_randomize(key, COTP_SECRET_MAX_LEN, GCRY_STRONG_RANDOM);
    return key;
}