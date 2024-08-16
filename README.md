# 2FA-PAM-implementation

# PAM TOTP Module

## Descripción

Este proyecto implementa un módulo PAM que añade soporte para autenticación de dos factores (2FA) utilizando TOTP, similar a Google Authenticator. El módulo se integra con servicios SSH en sistemas Linux.

## Estructura del Proyecto

- **include/**: Archivos de encabezado (.h) que definen las interfaces públicas.
- **src/**: Código fuente del módulo PAM y utilidades relacionadas.
- **management/**: Herramienta de gestión para administradores.
- **test/**: Pruebas unitarias para verificar la funcionalidad.
- **Makefile**: Archivo para compilar el proyecto.

## Compilación e Instalación

```bash
make all
