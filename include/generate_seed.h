#ifndef GENERATE_SEED_H
#define GENERATE_SEED_H

#include <stdio.h>
#include <stdlib.h>
#include <cotp.h>
#include <string.h>
#include "sodium.h"
#include "generate_seed.h"
#include "custom_base32_encode.h"
#include <gcrypt.h>

/**
 * Genera una semilla (seed) para TOTP y devuelve el URL en formato de cadena.
 *
 * @param secret_length Longitud del secreto a generar (en bytes).
 * @param base32_length Longitud del secreto codificado en Base32 (debe ser suficiente para la longitud del secreto).
 * @param issuer Nombre del emisor para el URL de TOTP (ej. "Example").
 * @param account Nombre de la cuenta para el URL de TOTP (ej. "user").
 * @return El URL de TOTP en formato de cadena, o NULL en caso de fallo.
 */
unsigned char* generate_seed();

#endif // SEED_GENERATOR_H
