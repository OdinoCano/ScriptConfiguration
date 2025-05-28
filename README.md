# PowerShell - Automatización de Configuración de Estaciones de Trabajo para Call Center

Este script en PowerShell automatiza la preparación de estaciones de trabajo Windows en un entorno de call center. Incluye configuración de usuarios, eliminación de bloatware, habilitación de RDP, instalación/configuración de Microsip y Chrome, y creación de accesos directos en la carpeta de inicio.

## Características

- Obtención de configuración desde una API o archivo local JSON.
- Creación/actualización de un usuario sin privilegios administrativos.
- Configuración del usuario administrador local (nombre SID `*-500`).
- Configuración de Microsip (`.ini`) con parámetros SIP dinámicos.
- Eliminación de aplicaciones preinstaladas (bloatware).
- Habilitación de Escritorio Remoto (RDP).
- Detección automática de rutas de instalación (Microsip, Chrome).
- Creación de accesos directos en carpeta `Startup`.
- Reinicio automático tras cambio de contraseña del administrador.


## Requisitos

- PowerShell 5.1 o superior
- Ejecución como **Administrador**
- Microsip y Google Chrome instalados previamente
- Acceso a internet para lectura desde API (opcional)

## Uso

### 1. Preparar el archivo de configuración `config.json`

Ejemplo:

```json
{
  "api": {
    "url": "http://mi-servidor.local/api"
  },
  "usuario": {
    "nombre": "agente01",
    "contrasegna": "Password123",
    "extenextension": "1001"
  },
  "administrador": {
    "contrasegna": "AdminPass456"
  },
  "chrome": {
    "urls": [
      "https://web.whatsapp.com/",
      "https://crm.miempresa.com/"
    ]
  }
}
```

## Funcionalidades Detalladas
### Get-Config
Obtiene la configuración desde una API remota o archivo local config.json.

### Set-Admin
Activa el usuario administrador local y cambia su contraseña.

### Find-Microsip, Find-Chrome
Localiza las rutas ejecutables de Microsip y Chrome en diferentes idiomas o ubicaciones comunes.

### Find-StartupFolder
Detecta la carpeta Startup del usuario, compatible con sistemas en español e inglés.

### Remove-Bloatware
Elimina aplicaciones innecesarias comunes en Windows (XBox, Solitaire, Cortana, Candy Crush, etc.).

### Microsip.ini
Modifica o crea el archivo de configuración MicroSIP.ini con la extensión SIP y ajustes predefinidos.

### Accesos Directos
Crea accesos directos a Chrome y Microsip en la carpeta de inicio del usuario.

### RDP
Habilita el Escritorio Remoto editando directamente el registro y agrega al usuario al grupo de usuarios de escritorio remoto (Remote Desktop Users).

## Consideraciones
El script realiza un reinicio forzado del sistema tras actualizar el usuario administrador.

Para sistemas sin RDP habilitado, el script puede fallar al modificar permisos de grupo.

Compatible con instalaciones Windows en inglés y español.

## Seguridad
Las contraseñas se manejan como SecureString internamente.

Se recomienda ejecutar este script en entornos controlados o imágenes preconfiguradas.
