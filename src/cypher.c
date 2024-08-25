#include "cypher.h"

// Función para aplicar padding PKCS7 al texto plano
void apply_padding(char *padded, const char *plaintext, size_t padded_len, size_t plaintext_len) {
    size_t pad_value = padded_len - plaintext_len;
    memcpy(padded, plaintext, plaintext_len);
    memset(padded + plaintext_len, pad_value, pad_value); // Agrega el padding
}

char* aes_encrypt_cbc(const char *plaintext, const char *password) {
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t gcry_ret;
    char *ciphertext;
    size_t plaintext_len = strlen(plaintext);
    size_t padded_len = ((plaintext_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE; // Redondea al bloque más cercano
    char iv[BLOCK_SIZE] = "1234567890abcdef";      // Vector de inicialización (IV)
    unsigned char key[KEY_SIZE];                   // Clave derivada
    char *padded_plaintext = malloc(padded_len);   // Texto plano con padding

    if (!padded_plaintext) {
        fprintf(stderr, "Error al asignar memoria para padded_plaintext\n");
        return NULL;
    }

    // Salt para PBKDF2 (en una aplicación real, usarías un salt aleatorio y lo almacenarías con el ciphertext)
    unsigned char salt[SALT_SIZE] = "fixed_salt1234";

    // Derivar la clave usando PBKDF2
    gcry_ret = gcry_kdf_derive(
        password,             // Entrada de la contraseña
        strlen(password),     // Longitud de la contraseña
        GCRY_KDF_PBKDF2,      // Tipo de KDF
        GCRY_MD_SHA256,       // Función hash (SHA-256)
        salt,                 // Salt
        SALT_SIZE,            // Tamaño del salt
        10000,                // Iteraciones (10000 es un buen punto de partida)
        KEY_SIZE,             // Longitud de la clave deseada
        key                   // Salida de la clave derivada
    );
    if (gcry_ret) {
        fprintf(stderr, "Error al derivar la clave: %s\n", gcry_strerror(gcry_ret));
        free(padded_plaintext);
        return NULL;
    }

    // Aplicar padding al texto plano
    apply_padding(padded_plaintext, plaintext, padded_len, plaintext_len);

    // Crear espacio para el texto cifrado
    ciphertext = malloc(padded_len);
    if (!ciphertext) {
        fprintf(stderr, "Error al asignar memoria para ciphertext\n");
        free(padded_plaintext);
        return NULL;
    }

    // Inicializar la biblioteca libgcrypt si es necesario
    if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) {
        gcry_check_version(NULL);
    }

    // Crear el manejador de cifrado
    gcry_ret = gcry_cipher_open(&cipher_hd, GCRY_CIPHER, GCRY_MODE, 0);
    if (gcry_ret) {
        fprintf(stderr, "Error al abrir el manejador de cifrado: %s\n", gcry_strerror(gcry_ret));
        free(ciphertext);
        free(padded_plaintext);
        return NULL;
    }

    // Establecer la clave de cifrado
    gcry_ret = gcry_cipher_setkey(cipher_hd, key, KEY_SIZE);
    if (gcry_ret) {
        fprintf(stderr, "Error al establecer la clave: %s\n", gcry_strerror(gcry_ret));
        gcry_cipher_close(cipher_hd);
        free(ciphertext);
        free(padded_plaintext);
        return NULL;
    }

    // Establecer el vector de inicialización (IV)
    gcry_ret = gcry_cipher_setiv(cipher_hd, iv, BLOCK_SIZE);
    if (gcry_ret) {
        fprintf(stderr, "Error al establecer el IV: %s\n", gcry_strerror(gcry_ret));
        gcry_cipher_close(cipher_hd);
        free(ciphertext);
        free(padded_plaintext);
        return NULL;
    }

    // Cifrar el texto con padding
    gcry_ret = gcry_cipher_encrypt(cipher_hd, ciphertext, padded_len, padded_plaintext, padded_len);
    if (gcry_ret) {
        fprintf(stderr, "Error al cifrar: %s\n", gcry_strerror(gcry_ret));
        gcry_cipher_close(cipher_hd);
        free(ciphertext);
        free(padded_plaintext);
        return NULL;
    }

    // Liberar recursos
    gcry_cipher_close(cipher_hd);
    free(padded_plaintext);

    return ciphertext;
}

// Función para eliminar el padding PKCS7 del texto desencriptado
size_t remove_padding(char *decrypted, size_t decrypted_len) {
    unsigned char pad_value = decrypted[decrypted_len - 1];
    if (pad_value > BLOCK_SIZE) {
        return decrypted_len; // No es padding válido, se devuelve la longitud original
    }
    return decrypted_len - pad_value;
}

char* aes_decrypt_cbc(const char *ciphertext, size_t ciphertext_len, const char *password) {
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t gcry_ret;
    char *decrypted;
    char iv[BLOCK_SIZE] = "1234567890abcdef";      // Vector de inicialización (IV)
    unsigned char key[KEY_SIZE];                   // Clave derivada

    // Salt para PBKDF2 (en una aplicación real, usarías el mismo salt que en la encriptación)
    unsigned char salt[SALT_SIZE] = "fixed_salt1234";

    // Derivar la clave usando PBKDF2
    gcry_ret = gcry_kdf_derive(
        password,             // Entrada de la contraseña
        strlen(password),     // Longitud de la contraseña
        GCRY_KDF_PBKDF2,      // Tipo de KDF
        GCRY_MD_SHA256,       // Función hash (SHA-256)
        salt,                 // Salt
        SALT_SIZE,            // Tamaño del salt
        10000,                // Iteraciones (10000 es un buen punto de partida)
        KEY_SIZE,             // Longitud de la clave deseada
        key                   // Salida de la clave derivada
    );
    if (gcry_ret) {
        fprintf(stderr, "Error al derivar la clave: %s\n", gcry_strerror(gcry_ret));
        return NULL;
    }

    // Crear espacio para el texto desencriptado
    decrypted = malloc(ciphertext_len);
    if (!decrypted) {
        fprintf(stderr, "Error al asignar memoria para decrypted\n");
        return NULL;
    }

    // Inicializar la biblioteca libgcrypt si es necesario
    if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) {
        gcry_check_version(NULL);
    }

    // Crear el manejador de cifrado
    gcry_ret = gcry_cipher_open(&cipher_hd, GCRY_CIPHER, GCRY_MODE, 0);
    if (gcry_ret) {
        fprintf(stderr, "Error al abrir el manejador de cifrado: %s\n", gcry_strerror(gcry_ret));
        free(decrypted);
        return NULL;
    }

    // Establecer la clave de cifrado
    gcry_ret = gcry_cipher_setkey(cipher_hd, key, KEY_SIZE);
    if (gcry_ret) {
        fprintf(stderr, "Error al establecer la clave: %s\n", gcry_strerror(gcry_ret));
        gcry_cipher_close(cipher_hd);
        free(decrypted);
        return NULL;
    }

    // Establecer el vector de inicialización (IV)
    gcry_ret = gcry_cipher_setiv(cipher_hd, iv, BLOCK_SIZE);
    if (gcry_ret) {
        fprintf(stderr, "Error al establecer el IV: %s\n", gcry_strerror(gcry_ret));
        gcry_cipher_close(cipher_hd);
        free(decrypted);
        return NULL;
    }

    // Desencriptar el texto cifrado
    gcry_ret = gcry_cipher_decrypt(cipher_hd, decrypted, ciphertext_len, ciphertext, ciphertext_len);
    if (gcry_ret) {
        fprintf(stderr, "Error al desencriptar: %s\n", gcry_strerror(gcry_ret));
        gcry_cipher_close(cipher_hd);
        free(decrypted);
        return NULL;
    }

    // Eliminar el padding PKCS7
    size_t decrypted_len = remove_padding(decrypted, ciphertext_len);

    // Liberar recursos
    gcry_cipher_close(cipher_hd);

    // Asegurarse de que el texto desencriptado esté terminado en '\0'
    decrypted[decrypted_len] = '\0';

    return decrypted;
}