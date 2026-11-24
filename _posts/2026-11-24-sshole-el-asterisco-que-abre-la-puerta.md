---
layout: research
title: "SSHole: el asterisco que abre la puerta"
date: 2026-11-24
author: "Fray García"
lead: "CVE-2026-123158 deja entrar por SSH, con cualquier contraseña de más de 256 caracteres, en cuentas que no tienen contraseña. Afecta a Alpine y a casi todo lo que usa musl sin PAM. El log que deja es un login normal: lo único raro es que esa cuenta no debería poder entrar con contraseña. Para detectarlo no basta con mirar el log, hay que saber qué cuentas tienes."
description: "Análisis defensivo de SSHole (CVE-2026-123158): por qué el crypt() de musl y el asterisco de /etc/shadow abren sshd sin PAM, qué deja en los logs, tres reglas Sigma y cómo comprobar en dos comandos si un Alpine está expuesto."
stack: "CVE-2026-123158 · OpenSSH · musl · Alpine Linux · sshd · doas · Sigma · CISA KEV"
toc:
  - title: "Introducción"
    id: introduccion
  - title: "Cómo un asterisco se convierte en contraseña"
    id: mecanismo
    children:
      - title: "La sal prestada"
        id: sal
      - title: "musl devuelve un asterisco cuando falla"
        id: musl
      - title: "El parche: cuatro caracteres"
        id: parche
  - title: "Quién está expuesto"
    id: exposicion
  - title: "Por qué esto le toca a una pyme"
    id: pyme
  - title: "El calendario y la explotación"
    id: calendario
  - title: "Qué deja en los logs"
    id: telemetria
  - title: "Detección"
    id: deteccion
    children:
      - title: "Regla 1 — login por contraseña en una cuenta sin contraseña"
        id: regla-cuenta
      - title: "Regla 2 — fallo y acierto seguidos"
        id: regla-secuencia
      - title: "Regla 3 — doas no interactivo"
        id: regla-doas
      - title: "Cómo se evaden estas reglas"
        id: evasion
  - title: "Mitigación y comprobación"
    id: mitigacion
  - title: "Conclusiones"
    id: conclusiones
  - title: "Limitaciones"
    id: limitaciones
  - title: "Referencias"
    id: referencias
---

## Introducción {#introduccion}

El 5 de noviembre OpenSSH publicó la versión **10.6p2** con una sola corrección, que el propio proyecto
califica de *critical security workaround*. El fallo, **CVE-2026-123158**, bautizado **SSHole** por
quien lo encontró, permite entrar por SSH **en una cuenta que no tiene contraseña** escribiendo
**cualquier contraseña de entre 257 y 1024 caracteres**. No hace falta conocer nada del sistema. Solo
afecta a una combinación concreta, sshd compilado o configurado **sin PAM** sobre la libc **musl**, y
esa combinación es la de Alpine Linux por defecto. El 9 de noviembre CISA lo metió en el KEV con
fecha límite el 12. Otra vez el tramo de [tres días]({{ '/research/el-plazo-de-cisa-paso-de-21-dias-a-3/' | relative_url }}).

Lo que me interesa de este fallo es la detección. En [FortiMail]({{ '/research/fortimail-el-correo-sale-por-el-archivado/' | relative_url }})
el atacante dejaba una cuenta nueva y en [PHP2Shell]({{ '/research/php2shell-el-crash-se-ve-el-exploit-no/' | relative_url }})
un worker reventado. Aquí no queda nada raro en el log. Un login con SSHole se registra exactamente
igual que un login legítimo con contraseña: `Accepted password for alpine`. GreyNoise, que tiene
sensores vulnerables desplegados, lo dice sin rodeos: desde fuera **no se distingue** si un login usó
el bypass o una contraseña de verdad.

Adelanto la conclusión: **la línea de log no basta, hace falta contexto.** La señal no está en el
mensaje, sino en que esa cuenta **no tiene contraseña** y aun así ha entrado con una. Eso solo lo ve
quien sabe qué cuentas tiene. Detectar SSHole es, antes que nada, un ejercicio de inventario.

## Cómo un asterisco se convierte en contraseña {#mecanismo}

El fallo no está en un sitio, está en el encaje de tres piezas que por separado son razonables. Lo
cuento según las explicaciones de Alpine y del investigador, Özgün Kültekin (Wakefield), y el diff
del parche de OpenSSH.

### La sal prestada {#sal}

En `/etc/shadow`, el segundo campo de cada cuenta guarda el hash de la contraseña, del tipo
`$6$sal$hash` para SHA-512. Las cuentas que **solo entran con clave SSH** no tienen hash; en Alpine
llevan un asterisco, `*`, que significa «aquí no hay contraseña válida». Desde Alpine 3.16, `root`
también lleva `*`, y las imágenes de nube de Alpine traen una cuenta `alpine` igual.

Cuando sshd funciona sin PAM, comprueba la contraseña él mismo: calcula `crypt(contraseña, sal)` y
compara el resultado con lo que hay en `shadow`. Para una cuenta con `*` no hay sal que usar. Así que
sshd, para no revelar con el tiempo de respuesta qué cuentas tienen contraseña (es la defensa contra la
enumeración de usuarios de CVE-2016-6210), **toma prestada la sal de otra cuenta** del sistema que sí
tenga un hash `$5$` o `$6$`. Basta con que exista **un** usuario con contraseña.

### musl devuelve un asterisco cuando falla {#musl}

La segunda pieza es de 2012. La implementación de SHA-crypt de musl rechaza claves de más de **256
bytes** (`KEY_MAX 256`). Y cuando `crypt()` falla, musl no devuelve `NULL` como glibc. Devuelve una
cadena que no pueda coincidir con ningún hash: **`*`** (o `x` si la sal empezaba por `*`). La idea era
buena: un programa que no comprueba el `NULL` no se cae.

Juntas las piezas, la comparación queda así:

<figure class="diagrama">
<svg viewBox="0 0 680 236" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Flujo del bypass: contraseña larga, sal prestada, crypt de musl falla y devuelve asterisco, que coincide con el asterisco de shadow">
  <rect x="2" y="20" width="150" height="56" rx="6" fill="#FFFFFF" stroke="#DADCDE"/>
  <text x="77" y="44" text-anchor="middle" font-family="'Inter',sans-serif" font-size="12.5" fill="#0A0A0A">contraseña de</text>
  <text x="77" y="62" text-anchor="middle" font-family="'JetBrains Mono',monospace" font-size="11.5" fill="#6B5D40">257–1024 bytes</text>
  <line x1="152" y1="48" x2="196" y2="48" stroke="#6B5D40" stroke-width="1.5"/>
  <polygon points="196,44 204,48 196,52" fill="#6B5D40"/>
  <rect x="206" y="20" width="200" height="56" rx="6" fill="#EBEEF1" stroke="#6B5D40"/>
  <text x="306" y="42" text-anchor="middle" font-family="'JetBrains Mono',monospace" font-size="11.5" fill="#0A0A0A">crypt(clave, sal $6$)</text>
  <text x="306" y="62" text-anchor="middle" font-family="'Inter',sans-serif" font-size="11" fill="#6F7376">sal prestada de otra cuenta</text>
  <line x1="406" y1="48" x2="450" y2="48" stroke="#6B5D40" stroke-width="1.5"/>
  <polygon points="450,44 458,48 450,52" fill="#6B5D40"/>
  <rect x="460" y="20" width="216" height="56" rx="6" fill="#FFFFFF" stroke="#DADCDE"/>
  <text x="568" y="42" text-anchor="middle" font-family="'Inter',sans-serif" font-size="12.5" fill="#0A0A0A">musl: clave &gt; 256 → falla</text>
  <text x="568" y="62" text-anchor="middle" font-family="'Inter',sans-serif" font-size="11" fill="#6F7376">y devuelve</text>
  <text x="626" y="63" text-anchor="middle" font-family="'JetBrains Mono',monospace" font-size="13" font-weight="700" fill="#6B5D40">"*"</text>
  <line x1="568" y1="76" x2="568" y2="112" stroke="#6B5D40" stroke-width="1.5"/>
  <polygon points="564,112 568,120 572,112" fill="#6B5D40"/>
  <rect x="206" y="122" width="470" height="56" rx="6" fill="#6B5D40"/>
  <text x="441" y="146" text-anchor="middle" font-family="'JetBrains Mono',monospace" font-size="13" fill="#FFFFFF">strcmp("*", "*") == 0</text>
  <text x="441" y="166" text-anchor="middle" font-family="'Inter',sans-serif" font-size="11.5" fill="#FFFFFF">el resultado del error coincide con el campo de shadow</text>
  <rect x="2" y="122" width="150" height="56" rx="6" fill="#FFFFFF" stroke="#DADCDE"/>
  <text x="77" y="146" text-anchor="middle" font-family="'Inter',sans-serif" font-size="12.5" fill="#0A0A0A">/etc/shadow</text>
  <text x="77" y="164" text-anchor="middle" font-family="'JetBrains Mono',monospace" font-size="11.5" fill="#6B5D40">alpine:*:…</text>
  <line x1="152" y1="150" x2="204" y2="150" stroke="#6B5D40" stroke-width="1.5" stroke-dasharray="4 3"/>
  <text x="2" y="208" font-family="'Inter',sans-serif" font-size="12.5" fill="#5C6166">glibc devuelve NULL al fallar y la comparación no llega a hacerse:</text>
  <text x="2" y="226" font-family="'Inter',sans-serif" font-size="12.5" fill="#5C6166">por eso Debian, Ubuntu o RHEL no están afectados.</text>
</svg>
<figcaption>El mismo carácter significa dos cosas: en <code>shadow</code>, «esta cuenta no tiene contraseña»; en la salida de <code>crypt()</code> de musl, «he fallado». sshd los compara y salen iguales.</figcaption>
</figure>

Hay un detalle más que importa para detectar. Según el sitio del investigador y la reproducción
independiente de Medcrypt en oss-security, el primer intento **no funciona**: hace falta un intento
fallido antes, por cómo sshd guarda en caché la sal elegida. En la práctica, el ataque es **dos
intentos de contraseña seguidos sobre la misma cuenta**, el segundo con éxito. Volveré a esto en la
Regla 2.

### El parche: cuatro caracteres {#parche}

El commit de OpenSSH (`4353fdc`, de Damien Miller) es pequeño y el mensaje deja clara la postura del
proyecto: no consideran que la causa raíz esté en OpenSSH, pero pueden evitarla. En
`sys_auth_passwd()`, dentro de `auth-passwd.c`, añade una constante y una condición antes de comparar:

```c
#define MIN_PASSWORD_HASH_LEN 4
...
return encrypted_password != NULL &&
    strlen(pw_password) >= MIN_PASSWORD_HASH_LEN &&
    strcmp(encrypted_password, pw_password) == 0;
```

Un hash real nunca mide menos de cuatro caracteres; `*` mide uno. Con eso, el campo de `shadow` deja de
poder coincidir con el error de musl. El resto del diff cambia cómo se copia y libera la memoria de la
sal y del hash (`xstrdup`, `freezero`), que es lo que encaja con la parte de los dos intentos.

## Quién está expuesto {#exposicion}

Las condiciones son cuatro y hacen falta todas:

| Condición | Valor afectado | Valor que corta el fallo |
|---|---|---|
| libc | musl | glibc / libxcrypt |
| PAM | sshd sin PAM, o `UsePAM no` | `UsePAM yes` |
| `PasswordAuthentication` | `yes` (el valor por defecto) | `no` |
| Cuenta objetivo | campo `*` en `shadow` y al menos otra cuenta con hash `$5$`/`$6$` | cuenta bloqueada con `!`, o ninguna cuenta con hash |

Alpine es el caso principal: su paquete `openssh-server` se compila sin PAM. Su aviso marca como
afectadas **todas las versiones que revisó**, de la 3.16 a la 3.24 y edge. NVD lo resume igual: sshd
anterior a 10.6p2 en Linux con musl y sin PAM. El investigador añade sistemas de la misma familia
(OpenWrt, Buildroot, Yocto) cuando llevan OpenSSH y no Dropbear; Medcrypt lo reprodujo en una imagen
Yocto de serie.

El escenario más directo lo describe Alpine: las imágenes de nube con *tiny-cloud*, de la 3.18.11 a la
3.24.3, traen una cuenta `alpine` con `*` en `shadow` y **`doas` sin contraseña**. Se entra como
`alpine` con el bypass y se pasa a root con `doas`. Entrar directamente como root necesita
`PermitRootLogin yes`, que no es el valor por defecto (`prohibit-password`), pero conviene revisarlo.

## Por qué esto le toca a una pyme {#pyme}

La reacción natural es pensar que nadie usa Alpine como servidor. No hace falta usarlo a propósito.
Alpine es la base de **la mayoría de las imágenes Docker pequeñas**, y aquí el problema son las que
llevan sshd dentro: imágenes para dar acceso SFTP a un proveedor, contenedores de «salto» para entrar a
una red, o la imagen `docker-sshd` de panubo, que tiene abierta una incidencia pidiendo la versión
corregida. Coolify, una plataforma popular para autoalojar aplicaciones en un VPS propio, instala
OpenSSH en Alpine sin desactivar la contraseña; ya hay una propuesta abierta para endurecerlo.

Es el patrón que veía en el [honeypot de la pyme turística]({{ '/research/que-recibe-realmente-una-pyme-turistica/' | relative_url }}):
el SSH expuesto recibe intentos de login desde el primer minuto, sin que nadie lo anuncie. Un
contenedor SFTP que montó alguien hace dos años para que la gestoría subiera ficheros, publicado en el
puerto 22 de un VPS, es exactamente el objetivo. Nadie lo recuerda, nadie lo actualiza y, con mucha
probabilidad, nadie recoge sus logs.

## El calendario y la explotación {#calendario}

<figure class="diagrama">
<ol class="cronologia">
<li><span class="crono-punto"></span><span class="crono-fecha">5 nov</span><span class="crono-titulo">OpenSSH 10.6p2</span><span class="crono-nota">Parche, aviso de Alpine y CVE</span></li>
<li class="hito"><span class="crono-punto"></span><span class="crono-fecha">5 nov</span><span class="crono-titulo">Exploit público</span><span class="crono-nota">Unas cuatro horas después</span></li>
<li class="hito"><span class="crono-punto"></span><span class="crono-fecha">7 nov</span><span class="crono-titulo">Explotación observada</span><span class="crono-nota">GreyNoise, en sensores vulnerables</span></li>
<li class="hito"><span class="crono-punto"></span><span class="crono-fecha">9 nov</span><span class="crono-titulo">Alta en KEV</span><span class="crono-nota">CISA, plazo hasta el 12</span></li>
<li class="crono-tramo">Del parche al exploit público, horas. Del exploit a la explotación, dos días.</li>
</ol>
<figcaption>Calendario de SSHole según el seguimiento de GreyNoise y el registro de NVD. A diferencia de PHP2Shell, aquí no hay explotación antes del parche: la ventana la abrió la publicación.</figcaption>
</figure>

La nota CVSS 3.1 que publicó MITRE es **8.1**, con complejidad **alta** (`AC:H`). Es lo esperable: hacen
falta varias condiciones que no dependen del atacante. Pero el registro de CISA en NVD tiene la parte
que importa: SSVC con explotación **activa** e impacto técnico **total**. Es otro caso en que la nota
CVSS dice poco de la urgencia, como pasaba con el [5.3 que también era un 9.8]({{ '/research/cve-2026-56164-un-53-que-tambien-es-un-98/' | relative_url }}).

El seguimiento público de GreyNoise da una idea de la escala. De unos **170 millones** de SYN al puerto
22 en sus sensores, solo identifica un puñado de intentos de explotación, y una cadena de actividad
posterior al acceso entre el **7 y el 8 de noviembre**, desde pocas direcciones y con un cliente
Paramiko (HASSH `a2de0f306611e0957be704f5b0e35a82`). Lo que se ejecutó tras entrar es reconocimiento y
preparación, y encaja con lo que se espera de una imagen Alpine de nube:

```text
cat /etc/os-release
id
uname -a
ps
apk add --no-cache python3
doas -n mkdir -p /opt/py3
dd if=/dev/zero of=/tmp/wtest bs=1M count=5
```

Dos cosas que señalar. Primero, no es un escaneo masivo; es una explotación **dirigida y escasa**, lo
que hace el ruido de fondo de SSH todavía más útil como camuflaje. Segundo, el atacante usa
**`doas -n`**: la opción no interactiva, que solo funciona si la cuenta puede escalar sin contraseña.
Es justo lo que trae la cuenta `alpine`.

## Qué deja en los logs {#telemetria}

**No he montado el laboratorio para este artículo**, así que no enseño líneas capturadas. Lo que sigue
es el formato estándar de sshd para estos eventos, con direcciones de documentación, y es lo que Alpine
dice que hay que buscar en `/var/log/messages`:

```text
sshd[2481]: Failed password for alpine from 203.0.113.50 port 51734 ssh2
sshd[2481]: Accepted password for alpine from 203.0.113.50 port 51734 ssh2
```

Esto es todo. sshd no registra la longitud de la contraseña ni nada del fallo de `crypt()`, porque desde
su punto de vista no ha fallado nada: la comparación salió bien. El problema es de diseño para quien
detecta: **el evento malicioso y el legítimo son idénticos**. Lo que los separa es información que no
está en la línea:

| Pregunta | ¿Está en el log? | Dónde está |
|---|---|---|
| ¿Esa cuenta tiene contraseña? | no | `/etc/shadow` del host |
| ¿Esa cuenta suele entrar con contraseña o con clave? | no directamente | histórico de `Accepted password` frente a `Accepted publickey` |
| ¿Hubo un intento fallido justo antes? | sí | la línea `Failed password` anterior |
| ¿Qué hizo después? | no en sshd | auditd, historial, telemetría de procesos |

Y una advertencia específica de Alpine y de los contenedores: **muchas veces no hay log**. Alpine usa
el `syslogd` de BusyBox, que hay que tener arrancado; un contenedor con sshd suele no tener syslog
alguno, y sshd solo escribe en la salida de error si se arrancó con `-e`. Antes de escribir una regla,
comprueba que esas líneas existen en algún sitio.

## Detección {#deteccion}

Las tres reglas trabajan con lo que se puede tener: el log de autenticación de sshd y, si hay suerte,
telemetría de procesos. Ninguna detecta el fallo en sí; detectan **sus consecuencias**.

| Regla | Fuente | Qué detecta | Fiabilidad | Ruido esperado |
|---|---|---|---|---|
| 1 — contraseña en cuenta sin contraseña | sshd | login imposible en condiciones normales | alta, si la lista es correcta | ninguno con un inventario bueno |
| 2 — fallo y acierto seguidos | sshd, correlación | la secuencia de dos intentos | media | usuarios que se equivocan una vez |
| 3 — `doas -n` | procesos | escalada sin contraseña | media | scripts de administración |

### Regla 1 — login por contraseña en una cuenta sin contraseña {#regla-cuenta}

La buena. Una cuenta con `*` en `shadow` **no puede** entrar con contraseña en un sistema sano. Si lo
hace, o el sistema es vulnerable y la han usado, o alguien le puso contraseña sin que lo sepas. Las dos
cosas merecen una alerta.

```yaml
title: Login SSH por contraseña en una cuenta que solo debería entrar con clave
id: bcfcf94e-a72b-4cc0-b6cb-b178d22b4eff
status: experimental
description: |
  Detecta un login SSH aceptado por contraseña en cuentas que, en Alpine y otros
  sistemas con musl, no tienen contraseña ('*' en /etc/shadow). Con sshd sin PAM y
  musl, CVE-2026-123158 (SSHole) permite entrar en esas cuentas con cualquier
  contraseña de 257 a 1024 bytes. Ampliar la lista con las cuentas de solo clave
  de cada entorno.
references:
  - https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
  - https://www.openssh.org/releasenotes.html#10.6p2
author: Fray García
date: 2026-11-24
tags:
  - attack.initial-access
  - attack.t1078.003
  - attack.t1190
  - cve.2026-123158
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Accepted password for alpine '
    - 'Accepted password for root '
  condition: keywords
falsepositives:
  - Una cuenta a la que alguien asignó contraseña sin documentarlo; también hay que investigarlo
level: high
```

La lista de cuentas es la regla. `alpine` y `root` son los valores de serie, pero **en cada entorno hay
que generar la lista real** de cuentas de solo clave. Se saca en un comando (está en la sección de
mitigación) y en un SIEM se mantiene mejor como lista de búsqueda que dentro de la regla.

### Regla 2 — fallo y acierto seguidos {#regla-secuencia}

La secuencia de dos intentos deja una forma reconocible: un `Failed password` y, segundos después, un
`Accepted password` para la misma cuenta desde la misma IP. Uso el formato de correlación de Sigma, que
necesita dos reglas base con nombre:

```yaml
title: sshd rechaza una contraseña
name: sshd_failed_password
id: a9909222-2d60-4a31-852e-6ecd6d9c0230
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Failed password for '
  condition: keywords
level: informational
---
title: sshd acepta una contraseña
name: sshd_accepted_password
id: 41bbe853-438f-419a-95bf-d3ceb33519ad
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Accepted password for '
  condition: keywords
level: informational
---
title: Contraseña rechazada y aceptada seguidas para la misma cuenta y origen
id: 6330fee3-8a6e-47b3-9097-749d8ad38ce3
status: experimental
description: |
  Un fallo de contraseña seguido de un acierto en menos de un minuto, misma cuenta
  y misma IP de origen. Es la forma de la explotación de CVE-2026-123158 (SSHole),
  que necesita un intento fallido antes del que entra. Por sí sola también la deja
  una persona que se equivoca una vez; cobra valor en hosts con musl y sin PAM, o
  sobre cuentas que normalmente entran con clave.
references:
  - https://sshhole.com/
  - https://www.openwall.com/lists/oss-security/2026/11/09/27
author: Fray García
date: 2026-11-24
tags:
  - attack.initial-access
  - attack.t1078
  - cve.2026-123158
correlation:
  type: temporal_ordered
  rules:
    - sshd_failed_password
    - sshd_accepted_password
  group-by:
    - user
    - src_ip
  timespan: 1m
falsepositives:
  - Personas que se equivocan al escribir la contraseña una vez
level: medium
```

El `group-by` supone que el SIEM ya extrae `user` y `src_ip` de la línea de sshd, cosa que hacen casi
todos los parsers de `auth.log`. Si no, la regla no correla nada.

### Regla 3 — doas no interactivo {#regla-doas}

La que cubre lo que pasa después. `doas -n` falla si la cuenta necesita contraseña, así que un atacante
lo usa para comprobar y aprovechar la escalada sin preguntar. En un servidor que nadie administra con
`doas` desde scripts, es raro.

```yaml
title: Uso no interactivo de doas
id: 2dafebd7-296b-40a2-9f4b-4f7fb31ad65c
status: experimental
description: |
  Detecta doas ejecutado con -n (no interactivo), que solo funciona si la cuenta
  puede escalar sin contraseña. Es la escalada que siguió a la explotación de
  CVE-2026-123158 en las imágenes de nube de Alpine, donde la cuenta 'alpine' tiene
  doas sin contraseña.
references:
  - https://sshole.events.greynoise.io/
author: Fray García
date: 2026-11-24
tags:
  - attack.privilege-escalation
  - attack.t1548.003
  - cve.2026-123158
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/doas'
    CommandLine|contains: ' -n '
  condition: selection
falsepositives:
  - Scripts de administración o despliegue que usan doas sin contraseña
level: medium
```

Necesita telemetría de procesos (auditd con reglas de `execve`, o un agente como el de Elastic). En un
contenedor Alpine sin agente, no hay nada que mirar.

### Cómo se evaden estas reglas {#evasion}

**La Regla 1 depende de la lista.** Si el atacante apunta a una cuenta de solo clave que no está en la
lista —la del proveedor de SFTP, la de un servicio—, no dispara. Por eso la lista tiene que salir del
`shadow` de cada máquina, no de mi ejemplo.

**La Regla 2 se rompe separando los intentos.** Si el intento fallido y el bueno llegan con más de un
minuto de diferencia, o desde IP distintas, la correlación no los une. Ampliar la ventana sube el ruido.

**La Regla 3 no ve a quien no use `doas -n`.** Un atacante que solo lea datos de la cuenta, o que use
otra vía para escalar, pasa por debajo.

**Sin log, no hay regla.** Es lo mismo que con PHP2Shell, pero peor: los contenedores con sshd son el
caso más expuesto y el que menos registra. **Que no salte nada no significa que no haya pasado.** En
este fallo, la certeza no está en el SIEM, está en la versión de OpenSSH y en `sshd -T`.

## Mitigación y comprobación {#mitigacion}

La comprobación cabe en dos comandos, y es lo primero que haría en cualquier Alpine o contenedor con
sshd. El primero lista las cuentas con `*` en `shadow`; el segundo, la configuración efectiva de sshd:

```bash
awk -F: '$2 == "*" { print $1 }' /etc/shadow
sshd -T | grep -Ei '^(usepam|passwordauthentication|permitrootlogin) '
```

Si el primero devuelve alguna cuenta y el segundo dice `passwordauthentication yes` sin
`usepam yes`, el sistema está expuesto hasta que se actualice. La salida del primero es, además, la
lista de la Regla 1.

| Medida | Qué corta | Coste | Qué deja fuera |
|---|---|---|---|
| Actualizar `openssh` (10.6p2 o el paquete corregido de Alpine) **y reiniciar sshd** | el fallo entero | casi ninguno | sin reiniciar, el daemon viejo sigue corriendo |
| `PasswordAuthentication no` | el fallo entero | nadie entra con contraseña | nada, si todo el mundo usa claves |
| Quitar `doas` sin contraseña a la cuenta `alpine` | la escalada a root | hay que dar otra vía de administración | el acceso como `alpine` |
| `PermitRootLogin prohibit-password` o `no` | el bypass directo sobre root | ninguno | otras cuentas con `*` |

Las versiones corregidas de Alpine, según su aviso:

| Rama | Paquete corregido |
|---|---|
| edge | `10.6_p2-r0` |
| 3.24 | `10.3_p1-r2` |
| 3.23 | `10.2_p1-r1` |
| 3.22 | `10.0_p1-r11` |
| 3.21 | `9.9_p2-r1` |

Para las ramas sin soporte (3.16 a 3.20) Alpine también publicó paquetes, pero un sistema en una rama
sin soporte tiene más problemas que este. En contenedores, **actualizar el paquete no sirve si nadie
reconstruye la imagen**: hay que subir la imagen base y volver a desplegar.

Una advertencia, porque es la tentación obvia: cambiar el `*` por `!` (cuenta bloqueada) corta el fallo,
pero en sshd sin PAM una cuenta bloqueada **tampoco puede entrar con clave**. Si la cuenta se usa con
clave, te dejas fuera. `PasswordAuthentication no` es el cambio limpio.

Y lo de siempre: el parche cierra la puerta, no echa a quien entró. Un Alpine con sshd expuesto entre el
5 de noviembre y la actualización hay que revisarlo: logins por contraseña en cuentas de solo clave,
claves nuevas en `authorized_keys`, servicios nuevos en `/etc/init.d` y cambios en `/etc/hosts`.

## Conclusiones {#conclusiones}

1. SSHole no es un fallo de memoria ni un exploit sofisticado: es un asterisco que significa dos cosas.
   En `shadow`, «sin contraseña»; en el `crypt()` de musl, «error». sshd sin PAM los comparaba.
2. Solo afecta a musl sin PAM, pero esa combinación es la de Alpine, y Alpine está debajo de muchísimas
   imágenes Docker. El riesgo para una pyme está en el contenedor con sshd que nadie recuerda.
3. El log de un login con SSHole es idéntico al de un login legítimo. **La detección necesita contexto**:
   saber qué cuentas no tienen contraseña. Sin inventario, no hay regla que valga.
4. La señal más fiable es un `Accepted password` en una cuenta de solo clave. La secuencia fallo-acierto
   y el `doas -n` posterior son señales de apoyo.
5. Para saber si estás expuesto no hace falta un SIEM: bastan dos comandos. La certeza está en la
   versión de OpenSSH y en `sshd -T`, no en la ausencia de alertas.

## Limitaciones {#limitaciones}

**Este artículo es un análisis de fuentes públicas, no un laboratorio propio.** No he reproducido el
fallo. Hay un laboratorio público en Docker (`leonjza/sshhole-lab`) y repetir este análisis sobre él,
con Elastic recogiendo los logs, es el siguiente paso natural; hasta entonces, las líneas de log que
enseño son el **formato estándar de sshd**, no eventos capturados de una explotación, y las direcciones
IP son de documentación.

El mecanismo lo explico según el aviso de Alpine, el sitio del investigador y el diff del parche. El
detalle de por qué hacen falta dos intentos (la caché de la sal) lo citan el investigador y Medcrypt; no
lo he verificado en el código. Los datos de explotación —fechas, comandos, HASSH— son de la página de
seguimiento de GreyNoise, que avisa de que no puede confirmar desde fuera si cada login usó el bypass o
una contraseña real. Los cuento como los publica, sin verificarlos por mi cuenta.

Las tres reglas **no están probadas contra telemetría**, ni de laboratorio ni de producción, y no las he
pasado por `sigma check` para este artículo. La Regla 2 usa el formato de correlación de Sigma, que no
todos los backends convierten. El `logsource` y los nombres de campo (`user`, `src_ip`) dependen de cómo
parsee cada SIEM los logs de sshd. Hay que probarlas en modo observación antes de desplegarlas.

## Referencias {#referencias}

<ol class="refs">
<li><a href="https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/">Security advisory: openssh-server password authentication bypass</a>. Alpine Linux, 5 de noviembre de 2026.</li>
<li><a href="https://www.openssh.org/releasenotes.html#10.6p2">OpenSSH 10.6p2 release notes</a>. OpenSSH.</li>
<li><a href="https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482">avoid password authn bypass (commit 4353fdc)</a>. Damien Miller, openssh-portable.</li>
<li><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-123158">CVE-2026-123158</a>. NIST National Vulnerability Database.</li>
<li><a href="https://sshhole.com/">*sshole</a>. Özgün Kültekin, Wakefield.</li>
<li><a href="https://www.openwall.com/lists/oss-security/2026/11/09/27">Re: "sshole": password authentication bypass: OpenSSH + musl libc</a>. Vidya Murthy (Medcrypt), oss-security, 9 de noviembre de 2026.</li>
<li><a href="https://sshole.events.greynoise.io/">SSHole (CVE-2026-123158) — seguimiento de explotación</a>. GreyNoise.</li>
<li><a href="https://github.com/leonjza/sshhole-lab">sshhole-lab</a>. Laboratorio en Docker, leonjza.</li>
<li><a href="https://github.com/panubo/docker-sshd/issues/93">docker-sshd: CVE-2026-123158</a>. Incidencia en GitHub, 7 de noviembre de 2026.</li>
<li><a href="https://github.com/coollabsio/coolify/discussions/12484">Harden Alpine SSH installation against CVE-2026-123158 (SSHole)</a>. Coolify, GitHub Discussions.</li>
<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-123158">Known Exploited Vulnerabilities Catalog</a>. CISA.</li>
<li><a href="https://sigmahq.io/">SigmaHQ</a>. Especificación del formato de reglas y de correlaciones.</li>
</ol>
