#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <cotp.h>
#include <gcrypt.h>
#define COTP_SECRET_MAX_LEN 20
#define GCRY_CIPHER GCRY_CIPHER_AES256   // Algoritmo de cifrado AES-256
#define GCRY_MODE GCRY_CIPHER_MODE_CBC   // Modo de operación CBC
#define KEY_SIZE 32                      // Tamaño de la clave para AES-256 (32 bytes)
#define BLOCK_SIZE 16                    // Tamaño del bloque AES (16 bytes)
#define SALT_SIZE 16                     // Tamaño del salt para PBKDF2


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

char *obtain_totp(unsigned char secret[COTP_SECRET_MAX_LEN], cotp_error_t *err) {
     return get_totp(secret, 6, 30, SHA1, err);
 }

char *obtain_seed(pam_handle_t *pamh) {
    // Abrir conexión a syslog
    openlog("pam_test", LOG_PID | LOG_CONS, LOG_AUTH);

    // Obtener el nombre de usuario
    const char *username;
    int retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "No se pudo obtener el nombre de usuario");
        closelog();
        return NULL;
    }
    syslog(LOG_ERR, "Nombre de usuario: %s", username);

    // Construir la ruta del archivo
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "/home/%s/2fa.txt", username);
    syslog(LOG_INFO, "Ruta del archivo: %s", file_path);

    // Abrir el archivo para lectura
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        syslog(LOG_ERR, "Error al abrir el archivo %s", file_path);
        closelog();
        return NULL;
    }
    syslog(LOG_INFO, "Archivo abierto con éxito");

    // Leer la seed del archivo y eliminar el salto de línea al final
    static char seed[256];
    if (fgets(seed, sizeof(seed), file) != NULL) {
        // Remover el salto de línea si está presente
        size_t len = strlen(seed);
        if (len > 0 && seed[len-1] == '\n') {
            seed[len-1] = '\0';
        }
        syslog(LOG_INFO, "Seed leída: %s", seed);
    } else {
        syslog(LOG_ERR, "Error al leer la seed del archivo");
        fclose(file);
        closelog();
        return NULL;
    }

    // Cerrar el archivo
    fclose(file);
    closelog();
    return seed;
}

// Implementación de pam_sm_authenticate
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Abrir conexión a syslog
    openlog("pam_test", LOG_PID | LOG_CONS, LOG_AUTH);

    syslog(LOG_INFO, "Entró a mi módulo");
    const struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    int retval;

    const char *password;
    // int retval;

    // Obtener la contraseña ingresada por el usuario
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to get authentication token");
        return retval;
    }
    syslog(LOG_ERR, "Contraseña ingresada: %s", password);

    // Obtener la estructura de conversación
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS || conv == NULL) {
        syslog(LOG_ERR, "No se pudo obtener la estructura de conversación");
        closelog();
        return retval;
    }

    // Configurar el mensaje que queremos mostrar al usuario para el input
    msg.msg_style = PAM_PROMPT_ECHO_ON;
    msg.msg = "Ingrese One-Time-Password: ";
    msgp = &msg;

    // Llamar a la función de conversación
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "La función de conversación falló");
        closelog();
        return retval;
    }

    // Aquí se debe obtener la seed desde un archivo o algún otro lugar
    char *seed = obtain_seed(pamh);

    aes_decrypt_cbc(seed, strlen(seed), password);
    syslog(LOG_ERR, "Seed: flagflag %s", aes_decrypt_cbc(seed, strlen(seed), password));
    cotp_error_t err;

    // Validar el input del usuario
    if (resp && resp->resp) {
        // Compara la respuesta del usuario con la seed
        if (strcmp(resp->resp, obtain_totp(aes_decrypt_cbc(seed, strlen(seed), password),&err)) == 0) {
            syslog(LOG_INFO, "Autenticación exitosa");
            free(resp->resp);
            free(resp);
            closelog();
            return PAM_SUCCESS;
        } else {
            syslog(LOG_ERR, "Error de autenticación: OTP incorrecto");
            free(resp->resp);
            free(resp);
            closelog();
            return PAM_AUTH_ERR;
        }
    }

    // Limpiar la memoria utilizada por la respuesta en caso de error
    if (resp) {
        if (resp->resp) {
            free(resp->resp);
        }
        free(resp);
    }

    syslog(LOG_ERR, "Error: No se obtuvo una respuesta válida");
    closelog();
    return PAM_AUTH_ERR;  // Autenticación fallida si no se pudo obtener la respuesta
}

// Implementación de otras funciones PAM requeridas
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
