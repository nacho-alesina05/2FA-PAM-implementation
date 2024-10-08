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

char* aes_decrypt_cbc(pam_handle_t *pamh, const char *ciphertext, size_t ciphertext_len, const char *password, int debug) {
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t gcry_ret;
    char *decrypted;
    char iv[BLOCK_SIZE] = "1234567890abcdef";      // Vector de inicialización (IV)
    unsigned char key[KEY_SIZE];                   // Clave derivada

    if(debug){
        syslog(LOG_INFO, "Starting decryption process");
    }

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
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error obtaining the key");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
        closelog();
        return NULL;
    }

    // Crear espacio para el texto desencriptado
    decrypted = malloc(ciphertext_len);
    if (!decrypted) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error allocating memory for decrypted text");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
        closelog();
        return NULL;
    }

    // Inicializar la biblioteca libgcrypt si es necesario
    if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) {
        gcry_check_version(NULL);
    }

    // Crear el manejador de cifrado
    gcry_ret = gcry_cipher_open(&cipher_hd, GCRY_CIPHER, GCRY_MODE, 0);
    if (gcry_ret) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error opening the cipher");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
        closelog();
        free(decrypted);
        return NULL;
    }

    // Establecer la clave de cifrado
    gcry_ret = gcry_cipher_setkey(cipher_hd, key, KEY_SIZE);
    if (gcry_ret) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error establishing the key");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
        gcry_cipher_close(cipher_hd);
        free(decrypted);
        return NULL;
    }

    // Establecer el vector de inicialización (IV)
    gcry_ret = gcry_cipher_setiv(cipher_hd, iv, BLOCK_SIZE);
    if (gcry_ret) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error establishing the IV");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
        gcry_cipher_close(cipher_hd);
        free(decrypted);
        return NULL;
    }

    // Desencriptar el texto cifrado
    gcry_ret = gcry_cipher_decrypt(cipher_hd, decrypted, ciphertext_len, ciphertext, ciphertext_len);
    if (gcry_ret) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error decrypting key");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
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
    if(debug){
        pam_syslog(pamh, LOG_INFO, "Finished decryption process with success");
    }
    return decrypted;
}

char *obtain_totp(unsigned char secret[COTP_SECRET_MAX_LEN], cotp_error_t *err) {
     return get_totp(secret, 6, 30, SHA1, err);
 }

char *obtain_seed(pam_handle_t *pamh, int debug, const char *username) {
    // Abrir conexión a syslog
    openlog("pam_2fa", LOG_PID | LOG_CONS, LOG_AUTH);
    
    syslog(LOG_INFO, "Username: %s", username);

    // Construir la ruta del archivo
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "/home/%s/2fa", username);
    syslog(LOG_INFO, "2FA file_path: %s", file_path);

    // Abrir el archivo para lectura
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "The file could not be opened");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
        closelog();
        return NULL;
    }

    // Leer la seed del archivo y eliminar el salto de línea al final
    static char seed[256];
    if (fgets(seed, sizeof(seed), file) != NULL) {
        // Remover el salto de línea si está presente
        size_t len = strlen(seed);
        if (len > 0 && seed[len-1] == '\n') {
            seed[len-1] = '\0';
        }
        syslog(LOG_INFO, "The encripted seed was obtained");
    } else {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Error obtaining seed from file");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user could not be authenticated");
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
    openlog("pam_2fa", LOG_PID | LOG_CONS, LOG_AUTH);

    //Ver si paso debug flag
    int i = 0;
    int debug = 0;
    while (i < argc) {
        const char *pam_option = argv[i];
        if (strcmp(pam_option, "debug") == 0) {
            debug = 1;
            break;
        }
        i++;
    }

    //Inicializo modulo
    if(debug){
        syslog(LOG_INFO, "2FA PAM Module: Debug mode enabled");
    }
    const struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    int retval;

    const char *password;

    //Obtener usuario
    const char *username;
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Username could not be obtained");
        }
            pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
        closelog();
        return retval;
    };

    // Obtener la contraseña ingresada por el usuario
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (retval != PAM_SUCCESS) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Failed to get authentication token");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
        closelog();
        return retval;
    }

    // Obtener la estructura de conversación
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS || conv == NULL) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Failed to get the conversation function");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
        closelog();
        return retval;
    }

    // Configurar el mensaje que queremos mostrar al usuario para el input
    msg.msg_style = PAM_PROMPT_ECHO_ON;
    msg.msg = "One-Time-Password: ";
    msgp = &msg;

    // Llamar a la función de conversación
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
        if(debug){
            pam_syslog(pamh, LOG_ERR, "Conversation function failed");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
        closelog();
        return retval;
    }

    // Aquí se debe obtener la seed desde un archivo o algún otro lugar
    char *seed = obtain_seed(pamh, debug, username);
    if(seed == NULL){
        if(debug){
            pam_syslog(pamh, LOG_ERR, "The seed could not be obtained");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
        closelog();
        return PAM_AUTH_ERR;
    }

    cotp_error_t err;

    // Validar el input del usuario
    if (resp && resp->resp) {
        // Compara la respuesta del usuario con la seed
        char* totp = obtain_totp(aes_decrypt_cbc(pamh, seed, strlen(seed), password, debug),&err);
        if(totp == NULL){
            if(debug){
            pam_syslog(pamh, LOG_ERR, "Error obtaining TOTP");
        }
        pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
        closelog();
        return PAM_AUTH_ERR;       
        }
        if (strcmp(resp->resp, totp) == 0) {
            syslog(LOG_INFO, "User %s authenticated successfully", username);
            free(resp->resp);
            free(resp);
            closelog();
            return PAM_SUCCESS;
        } else {
            if(debug){
            pam_syslog(pamh, LOG_ERR, "TOTP incorrect");
            }
            pam_syslog(pamh, LOG_ERR, "Session closed, the user %s could not be authenticated", username);
            closelog();
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
    if(debug){
        syslog(LOG_ERR, "Error: Not a valid response");
    }
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
