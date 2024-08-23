#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    pam_handle_t* pamh = NULL;
    int retval;

    // Iniciar la sesión PAM
    retval = pam_start("login", NULL, NULL, &pamh);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_start falló\n");
        return 1;
    }

    // Establecer el nombre de usuario en el manejador PAM
    const char* username = "usuario";  // Puedes reemplazar "usuario" con el nombre de usuario deseado
    retval = pam_set_item(pamh, PAM_USER, username);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_set_item falló\n");
        pam_end(pamh, retval);
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
        fprintf(stderr, "pam_end falló\n");
        return 1;
    }

    return 0;
}
