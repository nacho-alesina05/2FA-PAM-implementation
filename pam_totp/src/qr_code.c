#include "qr_code.h"
#include <qrencode.h>

// Genera y muestra el código QR para el URL dado.
void generate_qr_code(char *url) {
    QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_H, QR_MODE_8, 1);
    
    for (int y = 0; y < qrcode->width; y++) {
        for (int x = 0; x < qrcode->width; x++) {
            putchar(qrcode->data[y * qrcode->width + x] & 1 ? '#' : ' ');
        }
        putchar('\n');
    }

    QRcode_free(qrcode);
}
