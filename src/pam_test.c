#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <cotp.h>
#define COTP_SECRET_MAX_LEN 20


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
    syslog (LOG_ERR, "Seed obtenida: %s", seed);
    cotp_error_t err;
    char *totp = obtain_totp((unsigned char *)seed, &err);
    syslog(LOG_ERR, "TOTP obtenido: %s", totp);
    

     // Validar el input del usuario
    if (resp && resp->resp) {
        // Compara la respuesta del usuario con el TOTP generado
        if (strcmp(resp->resp, totp) == 0) {
            syslog(LOG_INFO, "Autenticación exitosa");
            free(resp->resp);
            free(resp);
            closelog();
            return PAM_SUCCESS;
        } else {
            syslog(LOG_ERR, "Error de autenticación: TOTP incorrecto");
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
