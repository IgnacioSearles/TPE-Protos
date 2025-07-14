# 🧦 SOCKS5 Proxy Server
Un servidor SOCKS5 configurable con soporte para autenticación, monitoreo y configuración en tiempo real mediante un protocolo personalizado (PCTP).

## ⚙️ Compilación de ejecutables
El proyecto genera dos ejecutables principales:

* 🛡️ server: el servidor SOCKS5 configurable.
* 🖥️ client: el cliente para monitorear y configurar el servidor.

### 🔨 Para compilar:
✅ Ambos ejecutables

```
make all
```
✅ Solo el servidor

```
make server
```
✅ Solo el cliente

```
make client
```

📁 Los ejecutables se generan en la carpeta /bin.

## 🚀 Ejecución del servidor
Ejecutá el servidor con:

```
./bin/socks5d [options]
```

📄 Opciones disponibles:
| Opción	      | Descripción                                   |
| --------------- | --------------------------------------------- |
| -h	          | Muestra ayuda y termina                       |
| -l <addr>	      | Dirección donde se servirá el proxy SOCKS     |
| -L <addr>	      | Dirección donde se servirá el protocolo PCTP  |
| -p <port>	      | Puerto SOCKS (por defecto: 1080)              |
| -P <port>	      | Puerto PCTP (por defecto: 8080)               |
| -u <user:pass>  |	Agrega un usuario ADMIN inicial (máximo 10)   |
| -v	          | Muestra la versión y termina                  |
| -d <log_level>  |	Nivel de log: DEBUG, INFO, WARN, ERROR, NONE  |

## 🖥️ Ejecución del cliente
El cliente se usa para interactuar con el servidor mediante PCTP:

```
./bin/client -h <addr> -p <port> -d <log_level>
```

## 📡 PCTP - Proxy Configuration and Tracking Protocol
Protocolo personalizado para configurar y monitorear el servidor SOCKS5 en tiempo real.

### 📌 Detalles:
Todos los comandos deben terminar en `\n` o `\r\n`.

Se requiere login antes de ejecutar comandos principales.

### 🔐 Comandos de login (en orden):

```
USER [nombre_usuario]
PASS [contraseña]
```
### 🧭 Comandos principales (requieren login previo):

```
LOGS [N]             # Muestra los últimos N logs (N es opcional)
STATS                # Estadísticas de uso del proxy
ADD ADMIN            # Agrega un nuevo usuario ADMIN (debe ser seguido de los comandos de login con los datos del nuevo usuario)
ADD BASIC            # Agrega un nuevo usuario BASIC (debe ser seguido de los comandos de login con los datos del nuevo usuario)
DEL [nombre_usuario] # Borra el usuario con [nombre_usuario]
LIST                 # Lista los usuarios registrados
CONFIG IO=[BYTES]    # Asigna tamaño a los buffers de IO
EXIT                 # Cierra la sesión
```
## 📚 Documentación y Estructura del Proyecto

### 📁 Estructura de Directorios

```
TPE-Protos/
├── 📋 Informe del desarrollo - Trabajo Practico Especial - Grupo 10.pdf
├── 📦 bin/                    # Ejecutables generados
│   ├── socks5d               # Servidor SOCKS5 con PCTP
│   └── client                # Cliente PCTP para administración
├── 🔧 src/                   # Código fuente completo
│   ├── client/               # Código del cliente PCTP
│   ├── server/               # Código del servidor principal
│   │   ├── socks5utils/      # Módulos del protocolo SOCKS5
│   │   ├── pctputils/        # Módulos del protocolo PCTP
│   │   ├── socks5.c/.h       # Controlador principal SOCKS5
│   │   ├── pctp.c/.h         # Controlador principal PCTP
│   │   └── server.c          # Punto de entrada del servidor
│   └── shared/               # Utilidades compartidas
│       ├── selector.c/.h     # Multiplexor I/O
│       ├── stm.c/.h          # Motor de máquinas de estado
│       ├── buffer.c/.h       # Buffers circulares
│       ├── parser.c/.h       # Parsers automáticos
│       └── logger.c/.h       # Sistema de logging
├── 📊 obj/                   # Archivos objeto (.o)
├── 🔨 Makefile              # Sistema de compilación
└── 📖 README.md             # Esta documentación
```

### 📄 Documentación Disponible

**📋 Informe Técnico**
- **Ubicación**: `Informe del desarrollo - Trabajo Practico Especial - Grupo 10.pdf`
- **Contenido**: Análisis técnico detallado, decisiones de diseño, testing y optimizaciones

**💻 Código Fuente**
- **Ubicación**: Directorio `src/`
- **Headers documentados**: Todos los archivos `.h` incluyen documentación
- **Arquitectura modular**: Separación clara entre SOCKS5, PCTP y utilidades

**🔧 Ejecutables**
- **Servidor**: `bin/socks5d` - Servidor principal con ambos protocolos
- **Cliente**: `bin/client` - Cliente administrativo PCTP
- **Generación**: Se crean automáticamente con `make all`

### 🔍 Elementos Solicitados

| Elemento | Ubicación | Descripción |
|----------|-----------|-------------|
| **Servidor SOCKS5** | `bin/socks5d` | Ejecutable principal del servidor |
| **Cliente PCTP** | `bin/client` | Cliente para administración remota |
| **Código fuente** | `src/` | Implementación completa modularizada |
| **Informe técnico** | `Informe del desarrollo...pdf` | Documentación académica detallada |
| **Documentación API** | `src/**/*.h` | Headers documentados |
| **Arquitectura** | `README.md` (este archivo) | Diagramas y explicación del sistema |
