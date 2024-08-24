#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cotp.h>
#include "obtain_totp.h"

static char* read_seed_from_file(const char *file_path) {
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    char *seed = NULL;
    size_t len = 0;
    size_t read = getline(&seed, &len, fp);
    if (read == -1) {
        perror("getline");
        free(seed);
        seed = NULL;
    }
    fclose(fp);
    return seed;
}

static char* obtain_file_path(){
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
        fprintf(stderr, "Error al obtener el directorio home\n");
        return NULL;
    }

    // Construye la ruta del archivo
    char *file_path = malloc(256);
    if (!file_path) {
        perror("malloc");
        return NULL;
    }
    snprintf(file_path, 256, "%s/2fa.txt", home_dir);
    return file_path;
}

// Implementación de pam_sm_authenticate
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    int retval;

    // Obtener la estructura de conversación
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS || conv == NULL) {
        fprintf(stderr, "No se pudo obtener la estructura de conversación\n");
        return retval;
    }

    // Configurar el mensaje que queremos mostrar al usuario para el input
    msg.msg_style = PAM_PROMPT_ECHO_OFF;  // Tipo de mensaje que requiere input del usuario (sin mostrar en pantalla)
    msg.msg = "Ingrese su código TOTP: ";  // Mensaje a mostrar
    msgp = &msg;

    // Llamar a la función de conversación
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "La función de conversación falló\n");
        return retval;
    }

    // Leer la semilla desde el archivo
    char* file_path = obtain_file_path();
    if (file_path == NULL) {
        return PAM_AUTH_ERR;
    }

    char* seed = read_seed_from_file(file_path);
    free(file_path);
    if (seed == NULL) {
        return PAM_AUTH_ERR;
    }

    // Obtener el TOTP usando la semilla
    cotp_error_t error;
    char* expected_totp = obtain_totp(seed, &error);
    free(seed);
    if (expected_totp == NULL || error != NO_ERROR) {
        fprintf(stderr, "Error al obtener el TOTP: %d\n", error);
        return PAM_AUTH_ERR;
    }

    // Validar el input del usuario comparándolo con el TOTP generado
    if (resp && resp->resp) {
        if (strcmp(resp->resp, "TSI") == 0) {
            free(resp->resp);
            free(resp);
            free(expected_totp);
            return PAM_SUCCESS;  // Autenticación exitosa
        } else {
            free(resp->resp);
            free(resp);
            free(expected_totp);
            return PAM_AUTH_ERR;  // Autenticación fallida
        }
    }

    // Limpiar la memoria utilizada en caso de error
    if (resp) {
        if (resp->resp) {
            free(resp->resp);
        }
        free(resp);
    }
    free(expected_totp);

    return PAM_AUTH_ERR;  // Autenticación fallida si no se pudo obtener la respuesta
}
