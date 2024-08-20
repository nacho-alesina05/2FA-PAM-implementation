#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Estructura para almacenar la respuesta de la conversación
struct pam_response* reply;

int conversation(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
    *resp = (struct pam_response*)malloc(sizeof(struct pam_response) * num_msg);
    if (*resp == NULL) {
        return PAM_CONV_ERR;
    }
    
    for (int i = 0; i < num_msg; i++) {
        printf("Mensaje recibido: %s\n", msg[i]->msg);  // Leer y mostrar el mensaje
        (*resp)[i].resp_retcode = 0;
        (*resp)[i].resp = strdup("ok"); // Responder con "ok" para continuar
    }
    return PAM_SUCCESS;
}

int main(int argc, char** argv) {
    pam_handle_t* pamh = NULL;
    struct pam_conv conv = { conversation, NULL };
    int retval;

    retval = pam_start("login", NULL, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed\n");
        return 1;
    }

    // Autenticación simple usando el módulo auth de PAM
    retval = pam_authenticate(pamh, 0);
    if (retval == PAM_SUCCESS) {
        printf("Autenticación exitosa\n");
    } else {
        printf("Autenticación fallida\n");
    }

    // Finaliza la sesión PAM
    retval = pam_end(pamh, retval);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_end failed\n");
        return 1;
    }

    return 0;
}
