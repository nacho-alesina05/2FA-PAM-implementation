#include "base32.h"
#include "totp.h"
#include "qr_code.h"
#include <openssl/rand.h>


int main() {
    unsigned char seed[20]; // Genera un seed de 160 bits (20 bytes)
    char base32_encoded_seed[33]; // Base32 requiere más espacio
    char url[256];
    char *username = "usuario";
    char *issuer = "MiEmpresa";

    // Genera el seed (usa una función segura para esto).
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        // Manejar el error en la generación de números aleatorios
        fprintf(stderr, "Error generando el seed seguro.\n");
    return 1;
    }

    // Convierte el seed a Base32.
    convert_to_base32(seed, base32_encoded_seed, sizeof(seed));

    // Genera el URL para Google Authenticator.
    generate_totp_url(base32_encoded_seed, username, issuer, url);

    // Genera y muestra el código QR.
    generate_qr_code(url);

    return 0;
}
