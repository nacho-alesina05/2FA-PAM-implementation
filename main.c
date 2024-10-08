#include <stdio.h>
#include <stdlib.h>
#include <qrencode.h>
#include <cotp.h>
#include <string.h>
#include "generate_seed.h"
#include "custom_base32_encode.h"
#include "obtain_totp.h"
#include "cypher.h"
#include <sys/stat.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define COTP_SECRET_MAX_LEN 20
#define COTP_SECRET_BASE32_LEN 32
#define BASE32_SECRET_LEN 32
#define GCRY_CIPHER GCRY_CIPHER_AES256   // Algoritmo de cifrado AES-256
#define GCRY_MODE GCRY_CIPHER_MODE_CBC   // Modo de operación CBC
#define KEY_SIZE 32                      // Tamaño de la clave para AES-256 (32 bytes)
#define IV_SIZE 16
#define SALT_SIZE 16

struct user_data {
    const char *password;
};

int my_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *aresp;
    struct user_data *udata = (struct user_data *) appdata_ptr;

    // Verifica que haya al menos un mensaje
    if (num_msg <= 0) return PAM_CONV_ERR;

    // Asigna memoria para las respuestas
    aresp = calloc(num_msg, sizeof(struct pam_response));
    if (aresp == NULL) return PAM_CONV_ERR;

    // Procesa cada mensaje
    for (int i = 0; i < num_msg; i++) {
        aresp[i].resp_retcode = 0;
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            // Siempre responde con la misma contraseña
            aresp[i].resp = strdup(udata->password);
        } else {
            // Responde con una cadena vacía para otros tipos de mensajes
            aresp[i].resp = strdup("");
        }
    }

    // Asigna el puntero a las respuestas
    *resp = aresp;
    return PAM_SUCCESS;
}


int validate_password(const char *user, const char *password) {
    pam_handle_t *pamh = NULL;
    int retval;

    struct user_data udata = {password};
    const struct pam_conv conv = {my_conv, &udata};

    retval = pam_start("login", user, &conv, &pamh);

    if (retval == PAM_SUCCESS) {
        retval = pam_authenticate(pamh, 0); // Check the password
    }

    pam_end(pamh, retval);

    return (retval == PAM_SUCCESS ? 1 : 0); // Return 1 if successful, 0 if not
}

int main() {

    
    const char *username = getenv("USER");  // Obtener el nombre de usuario del entorno
    if (!username) {
        return 1;
    }
    
    // Solicitar la contraseña para cifrar con un máximo de 3 intentos
    char *password;

    password = getpass("Introduce la contraseña para cifrar: ");
    // Eliminar el salto de línea al final si es necesario
    size_t len = strlen(password);
    if (len > 0 && password[len-1] == '\n') {
        password[len-1] = '\0';
    }
    password[strcspn(password, "\n")] = '\0'; // Eliminar el salto de línea

    // Verificar la contraseña ingresada contra la contraseña del sistema usando PAM
    if (validate_password(username, password)) {
        printf("Contraseña verificada correctamente.\n");
    } else {
        printf("Contraseña incorrecta.\n");
        return EXIT_FAILURE;
    }

    // Obtiene el directorio home del usuario actual
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
        return EXIT_FAILURE;
    }

    // Construye la ruta del archivo
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/2fa", home_dir);


    // Verificar si el archivo ya existe
    FILE *file = fopen(file_path, "r");
    if (file != NULL) {
        printf("2fa file does already exists.\n");
        fclose(file);
    } else {
        // Generar la semilla usando generate_seed
        unsigned char* secret = generate_seed();

        // Convertir la clave secreta a formato Base32
        char base32_secret[COTP_SECRET_BASE32_LEN + 1];  // +1 para el carácter nulo
        custom_base32_encode(secret, COTP_SECRET_MAX_LEN, base32_secret);

        // Abre el archivo en modo escritura, creándolo si no existe
        file = fopen(file_path, "w");
        if (file == NULL) {
            perror("Error al abrir el archivo");
            return EXIT_FAILURE;
        }

        // Escribe la semilla en el archivo
        fprintf(file, "%s\n", aes_encrypt_cbc(base32_secret, password));
        // Cierra el archivo
        fclose(file);

        // Generar el código QR con la URL de configuración de TOTP
        char url[256];
        snprintf(url, sizeof(url), "otpauth://totp/%s?secret=%s&issuer=%s", "user", base32_secret, "Example");
        QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        if (!qrcode) {
            fprintf(stderr, "Error generating QR code.\n");
            return 1;
        }

        // Imprimir el QR en ASCII
        for (int y = 0; y < qrcode->width; y++) {
            for (int x = 0; x < qrcode->width; x++) {
                printf(qrcode->data[y * qrcode->width + x] & 1 ? "██" : "  ");
            }
            printf("\n");
        }
        QRcode_free(qrcode);
        printf("\n");

        // Cambia los permisos del archivo para que solo el dueño pueda leer y escribir
        if (chmod(file_path, S_IRUSR | S_IWUSR) != 0) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
