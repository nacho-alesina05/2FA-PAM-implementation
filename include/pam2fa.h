#ifndef PAM2FA_H
#define PAM2FA_H

#include <security/pam_appl.h>
#include <security/pam_modules.h>

// Declaraciones de funciones
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);

#endif /* PAM2FA_H */
