#ifndef CYPHER_H
#define CYPHER_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

#define GCRY_CIPHER GCRY_CIPHER_AES256   // Algoritmo de cifrado AES-256
#define GCRY_MODE GCRY_CIPHER_MODE_CBC   // Modo de operación CBC
#define KEY_SIZE 32                      // Tamaño de la clave para AES-256 (32 bytes)
#define BLOCK_SIZE 16                    // Tamaño del bloque AES (16 bytes)
#define SALT_SIZE 16                     // Tamaño del salt para PBKDF2

void apply_padding(char *padded, const char *plaintext, size_t padded_len, size_t plaintext_len);
char* aes_encrypt_cbc(const char *plaintext, const char *password);
size_t remove_padding(char *decrypted, size_t decrypted_len);
char* aes_decrypt_cbc(const char *ciphertext, size_t ciphertext_len, const char *password);

#endif // CYPHER_H
