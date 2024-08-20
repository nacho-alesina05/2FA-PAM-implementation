#include <security/pam_appl.h>  // Necesario para pam_get_user
#include <security/pam_modules.h> // Necesario para PAM_EXTERN
#include <security/pam_ext.h> // Necesario para pam_get_authtok
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "generate_seed.h"
//#include "custom_base32_encode.h"
//#include "obtain_totp.h"
//#include "pam2fa.h"

#define MAX_SECRET_LEN 32

#define MAX_SECRET_LEN 32
#define SECRET_FILE "/etc/2fa/secret_base32.txt"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Mensaje de depuración para verificar el enlace del módulo
    printf("Hola mundo desde pam2fa.so\n");
    fflush(stdout);  // Asegúrate de que el mensaje se imprima inmediatamente

    // Aquí puedes agregar la lógica de autenticación si lo deseas

    return PAM_SUCCESS;  // Autenticación exitosa para fines de prueba
}

// Función para configurar credenciales del módulo PAM (en este caso, no hace nada)
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

// PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//     const char *user;
//     int retval = pam_get_user(pamh, &user, "Username: ");
//     if (retval != PAM_SUCCESS) {
//         return retval;
//     }

//     // Leer la semilla en Base32 desde el archivo
//     char stored_base32_secret[MAX_SECRET_LEN];
//     FILE *file = fopen(SECRET_FILE, "r");
//     if (!file) {
//         perror("Error opening secret file");
//         return PAM_AUTH_ERR;
//     }
//     if (!fgets(stored_base32_secret, sizeof(stored_base32_secret), file)) {
//         fclose(file);
//         perror("Error reading secret file");
//         return PAM_AUTH_ERR;
//     }
//     fclose(file);
//     stored_base32_secret[strcspn(stored_base32_secret, "\n")] = '\0';  // Remove newline character

//     // Obtener el TOTP
//     cotp_error_t error;
//     char *expected_totp = obtain_totp(stored_base32_secret, &error);
//     if (error) {
//         fprintf(stderr, "Error obtaining TOTP: %d\n", error);
//         return PAM_AUTH_ERR;
//     }

//     // Preguntar al usuario por el TOTP
//     const char *user_totp;
//     retval = pam_get_authtok(pamh, PAM_AUTHTOK, &user_totp, "TOTP: ");
//     if (retval != PAM_SUCCESS) {
//         free(expected_totp);
//         return retval;
//     }

//     // Validar el TOTP ingresado por el usuario
//     if (strcmp(user_totp, expected_totp) == 0) {
//         free(expected_totp);
//         return PAM_SUCCESS;  // Autenticación exitosa
//     } else {
//         free(expected_totp);
//         return PAM_AUTH_ERR;  // Autenticación fallida
//     }
// }

// PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//     return PAM_SUCCESS;
// }
