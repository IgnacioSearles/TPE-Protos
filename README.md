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
./bin/server [options]
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
EXIT                 # Cierra la sesión
```
