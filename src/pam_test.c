#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *obtain_seed(){
    return "JBSWY3DPEHPK3PXP";
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
    msg.msg_style = PAM_PROMPT_ECHO_ON;
    msg.msg = "Ingrese One-Time-Password: ";
    msgp = &msg;

    // Llamar a la función de conversación
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "La función de conversación falló\n");
        return retval;
    }

    // Validar el input del usuario
    if (resp && resp->resp) {
        //no es obtain seed sino el totp con dicha seed
        if (strcmp(resp->resp, obtain_seed()) == 0) {
            free(resp->resp);
            free(resp);
            return PAM_SUCCESS;
        } else {
            free(resp->resp);
            free(resp);
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
