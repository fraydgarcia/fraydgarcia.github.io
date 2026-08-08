---
layout: research
title: "La passkey sincronizada no vive en el TPM"
date: 2026-08-08
author: "Fray García"
lead: "Unit 42 ha publicado tres ataques contra las passkeys sincronizadas de Google que funcionan desde una cuenta de usuario sin privilegios. La investigación describe cómo se roban; casi no dice cómo se detectan. Esto es lo segundo: tres reglas Sigma y la telemetría que hace falta para que sirvan de algo."
description: "Análisis defensivo de los ataques Pass-ta-key, Silver y Golden contra las passkeys sincronizadas de Chrome: qué protege realmente el TPM, por qué el relying party no puede avisarte, y tres reglas Sigma para detectar el robo desde el endpoint."
stack: "Sigma · Sysmon · WebAuthn/FIDO2 · Windows Event Logs · Chrome"
toc:
  - title: "Introducción"
    id: introduccion
  - title: "Qué protege realmente el TPM"
    id: que-protege-el-tpm
  - title: "Los tres ataques, en lo que importa para detectarlos"
    id: los-tres-ataques
    children:
      - title: "Pass-ta-key: firmar sin llegar a tener la clave"
        id: pass-ta-key
      - title: "Silver: registrar tu propia clave de verificación"
        id: silver
      - title: "Golden: la llave maestra en memoria"
        id: golden
  - title: "Por qué el servicio no te va a avisar"
    id: signcount
  - title: "Detección en el endpoint"
    id: deteccion
    children:
      - title: "Regla 1 — lectura de los ficheros de passkeys"
        id: regla-lectura
      - title: "Regla 2 — borrado del estado del enclave"
        id: regla-borrado
      - title: "Regla 3 — lectura de la memoria de Chrome"
        id: regla-memoria
      - title: "Qué hacer con los falsos positivos"
        id: falsos-positivos
      - title: "Cómo se evaden estas tres reglas"
        id: evasion
  - title: "Qué se traslada a un despliegue corporativo"
    id: corporativo
  - title: "Conclusiones"
    id: conclusiones
  - title: "Limitaciones"
    id: limitaciones
  - title: "Referencias"
    id: referencias
---

## Introducción {#introduccion}

El argumento comercial de las passkeys es que la clave privada nunca sale del dispositivo, así que
no hay nada que robar. Es cierto para una passkey ligada a hardware. Para una passkey
**sincronizada** — la que Google guarda en tu cuenta para que aparezca en el móvil, en el portátil y
en el ordenador de casa — no lo es del todo, y esa diferencia es la que Unit 42 convirtió el 3 de
agosto en tres ataques con nombre propio: *Pass-ta-key*, *Silver Pass-ta-key* y *Golden
Pass-ta-key*.

Ninguno de los tres necesita privilegios de administrador. Ninguno necesita que el usuario
desbloquee el equipo ni que haga clic en nada. Es decir: entran dentro de lo que ya hace hoy
cualquier infostealer que llega por un instalador troyanizado.

La investigación de Unit 42 está bien hecha y es muy detallada del lado del ataque. Del lado de
quien tiene que darse cuenta, se queda en una línea: *monitoriza el uso anómalo de passkeys con tu
agente de seguridad de endpoint*. Eso no es una detección, es un deseo. Este artículo intenta cerrar
ese hueco: qué evento concreto queda, qué regla lo caza, y — la parte incómoda — qué telemetría hay
que activar antes, porque con Sysmon recién instalado dos de estos tres ataques no dejan rastro.

## Qué protege realmente el TPM {#que-protege-el-tpm}

Conviene separar dos claves que se confunden constantemente, porque de esa confusión sale toda la
falsa sensación de seguridad.

La **clave de identidad de dispositivo** sí está respaldada por el TPM. Chrome la genera, el chip la
envuelve con una clave que no sale del hardware y Chrome guarda el blob envuelto en un fichero,
`passkey_enclave_state`. Solo esa máquina puede desenvolverlo. Hasta aquí, bien.

La **clave privada de la passkey** no está ahí. Está cifrada dentro de la base de datos de
sincronización de Chrome, como registros `WebauthnCredentialSpecifics` en formato proto:

```text
%LocalAppData%\Google\Chrome\User Data\<Perfil>\Sync Data\LevelDB
```

Ese fichero se lee sin ser administrador. Aunque las claves privadas van cifradas, el resto no: qué
servicios usan passkey, con qué nombre de usuario y qué identificadores de credencial. Para un
atacante que aún no sabe dónde apuntar, eso ya es un mapa.

<figure>
<svg viewBox="0 0 900 450" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Diagrama: la clave de identidad del dispositivo está sellada en el TPM, mientras que el blob envuelto, la base de datos de sincronización con las claves de passkey y el Security Domain Secret en memoria quedan dentro del alcance de un proceso sin privilegios">
  <g font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">
    <text x="88" y="26">DENTRO DEL TPM</text>
  </g>
  <rect x="88" y="38" width="380" height="72" fill="none" stroke="#8A7A5A" stroke-width="1.5"/>
  <text x="106" y="70" font-family="'Poppins', sans-serif" font-size="13" font-weight="600" fill="#EDEAE6">Clave de identidad de dispositivo</text>
  <text x="106" y="92" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">GENERADA Y SELLADA POR EL HARDWARE</text>
  <text x="488" y="76" font-family="'Poppins', sans-serif" font-size="12" fill="rgba(237,234,230,.80)">La única pieza que el hardware protege de verdad.</text>

  <line x1="278" y1="110" x2="278" y2="170" stroke="rgba(237,234,230,.28)" stroke-width="1"/>
  <path d="M274,168 L278,176 L282,168 Z" fill="rgba(237,234,230,.28)"/>
  <text x="292" y="134" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">CHROME LA GUARDA ENVUELTA</text>

  <rect x="76" y="140" width="794" height="250" fill="none" stroke="rgba(237,234,230,.14)" stroke-width="1" stroke-dasharray="3 4"/>
  <text x="856" y="160" font-family="'Share Tech Mono', monospace" font-size="10" fill="#8A7A5A" text-anchor="end">ALCANCE DEL MALWARE SIN PRIVILEGIOS</text>

  <g font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">
    <text x="88" y="164">EN DISCO</text>
  </g>
  <rect x="88" y="176" width="370" height="88" fill="none" stroke="rgba(237,234,230,.14)" stroke-width="1"/>
  <text x="106" y="206" font-family="'Share Tech Mono', monospace" font-size="13" fill="#EDEAE6">passkey_enclave_state</text>
  <text x="106" y="228" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">BLOB DE LA CLAVE DE IDENTIDAD</text>
  <text x="106" y="248" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">SE IMPORTA Y EL TPM FIRMA A PETICIÓN</text>

  <rect x="486" y="176" width="370" height="88" fill="none" stroke="rgba(237,234,230,.14)" stroke-width="1"/>
  <text x="504" y="206" font-family="'Share Tech Mono', monospace" font-size="13" fill="#EDEAE6">Sync Data\LevelDB</text>
  <text x="504" y="228" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">WebauthnCredentialSpecifics</text>
  <text x="504" y="248" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">CLAVES CIFRADAS · SERVICIOS EN CLARO</text>

  <g font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">
    <text x="88" y="296">EN MEMORIA DEL PROCESO DE CHROME</text>
  </g>
  <rect x="88" y="308" width="470" height="64" fill="none" stroke="rgba(237,234,230,.14)" stroke-width="1"/>
  <text x="106" y="338" font-family="'Poppins', sans-serif" font-size="13" font-weight="600" fill="#EDEAE6">Security Domain Secret · 32 bytes</text>
  <text x="106" y="358" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">DESCIFRA TODAS LAS PASSKEYS DE LA CUENTA</text>
  <text x="580" y="334" font-family="'Poppins', sans-serif" font-size="12" fill="rgba(237,234,230,.80)">En claro durante los flujos</text>
  <text x="580" y="352" font-family="'Poppins', sans-serif" font-size="12" fill="rgba(237,234,230,.80)">de recuperación.</text>

  <text x="88" y="416" font-family="'Poppins', sans-serif" font-size="12" fill="rgba(237,234,230,.80)">El TPM impide copiar la clave de identidad. No impide que otro proceso la use.</text>
  <text x="88" y="442" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">DÓNDE VIVE CADA CLAVE EN UNA PASSKEY SINCRONIZADA · CHROME SOBRE WINDOWS</text>
</svg>
<figcaption>Solo el recuadro superior está protegido por hardware, y lo que protege no es la passkey: es la identidad del dispositivo. Todo lo que cae dentro del recuadro discontinuo lo alcanza un proceso que corre como el usuario, sin elevación.</figcaption>
</figure>

Y aquí está el detalle que sostiene todo lo demás: **el blob envuelto por el TPM se puede usar sin
extraerlo**. Un proceso sin privilegios lo carga con `NCryptImportKey` y le pide firmas con
`NCryptSignHash`, y es el propio TPM quien firma. La clave no se roba nunca. Se toma prestada.

> El TPM garantiza que la clave no se copie. No garantiza que solo la use quien debe.

## Los tres ataques, en lo que importa para detectarlos {#los-tres-ataques}

No voy a reproducir la cadena completa — está en el artículo original. Me quedo con lo que deja
huella.

### Pass-ta-key: firmar sin llegar a tener la clave {#pass-ta-key}

El malware lee `passkey_enclave_state`, importa el blob con las APIs CNG de Windows
(`NCryptOpenStorageProvider`, `NCryptImportKey`, `NCryptSignHash`) y con las firmas que produce el
TPM se hace pasar por el dispositivo ante el autenticador en la nube de Google. Levanta un WebSocket
imitando el comportamiento legítimo de Chrome, firma el handshake y ya está dentro del flujo de
aserción.

El remate depende del otro lado: cuando el servicio no comprueba de verdad el flag *User Verified*
de la respuesta, la exigencia de biometría o PIN se convierte en decorativa.

**Rastro:** lectura de un fichero concreto y uso de CNG. Lo segundo es indetectable en la práctica
(medio Windows llama a esas APIs). Lo primero es la señal.

### Silver: registrar tu propia clave de verificación {#silver}

El atacante borra `passkey_enclave_state` o lanza un `device/forget`. Chrome se ve obligado a
re-registrar el dispositivo, y durante ese re-onboarding hay una ventana — el estado
`uv_key_pending` — en la que se acepta el registro de una clave de verificación de usuario mediante
`device/add_uv_key` **sin validar su origen hardware**. El atacante registra la suya. A partir de
ahí puede autenticarse desde su propia máquina, sin el dispositivo de la víctima delante.

**Rastro:** el borrado del fichero de estado, y su recreación inmediata. Es el mejor indicador de los
tres, porque el borrado es un acto deliberado y raro. Añadido: la víctima ve un aviso de
re-registro que no ha pedido.

### Golden: la llave maestra en memoria {#golden}

Durante los flujos de recuperación, el *Security Domain Secret* — 32 bytes que descifran **todas**
las passkeys sincronizadas de la cuenta — aparece en el proceso de Chrome. Llegó a salir en claro en
el registro de `chrome://device-log/FIDO`; Google quitó ese volcado tras la divulgación
responsable, pero el secreto sigue estando en memoria.

Lo llaman *Golden* por analogía con el Golden Ticket de Kerberos, y la analogía aguanta: quien lo
tiene descifra todo el conjunto y no hay rotación posible.

**Rastro:** un proceso que no es Chrome abriendo Chrome con permiso de lectura de memoria. Esto sí
lo ve Sysmon de serie.

## Por qué el servicio no te va a avisar {#signcount}

Hay una defensa clásica en WebAuthn contra credenciales clonadas: el contador de firmas. Cada
aserción incrementa un número; si el servidor ve un valor que retrocede o se repite, sabe que hay dos
copias de la misma credencial en circulación.

Con passkeys sincronizadas ese contador viene constante. Unit 42 lo dice sin adornos: los servicios
tienen visibilidad limitada del uso no autorizado de credenciales sincronizadas. Google respondió que
mantener contadores coherentes entre varios dispositivos y plataformas es difícil de implementar, lo
cual es verdad y no cambia la consecuencia.

La consecuencia, para quien defiende, es la siguiente: **la detección del lado del relying party está
desactivada por diseño**. No hay evento de servidor esperando a que lo correles. Si el robo se va a
ver en algún sitio, es en el endpoint, y solo si estaba instrumentado antes.

## Detección en el endpoint {#deteccion}

Antes de las reglas, la mala noticia que ninguna guía de despliegue de Sysmon dice lo bastante alto:

**Sysmon no registra lecturas de fichero.** El Event ID 11 es creación o sobrescritura. Un malware
que se limita a *leer* `passkey_enclave_state` y la LevelDB de sincronización — que es exactamente lo
que hace *Pass-ta-key* — no genera ni un evento de Sysmon.

Para verlo hacen falta dos cosas: activar la auditoría de acceso a objetos del sistema
(«Auditar acceso a objetos» → *Sistema de archivos*) y poner una SACL sobre esas rutas. Solo entonces
aparece el Event ID 4663 en el registro de seguridad. Sin ese paso previo, la Regla 1 no dispara
nunca — no porque esté mal escrita, sino porque no hay dato.

<figure>
<svg viewBox="0 0 900 356" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Matriz de cobertura: Pass-ta-key deja lectura de ficheros y necesita Event ID 4663 con auditoría y SACL; Silver deja el borrado del enclave y necesita Sysmon 23 o 26 con la ruta incluida en la configuración; Golden deja lectura de memoria de Chrome y lo cubre Sysmon 10 de serie">
  <g font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">
    <text x="88" y="44">ATAQUE</text>
    <text x="290" y="44">QUÉ DEJA</text>
    <text x="540" y="44">FUENTE</text>
    <text x="690" y="44">TELEMETRÍA</text>
  </g>
  <line x1="84" y1="58" x2="870" y2="58" stroke="rgba(237,234,230,.28)" stroke-width="1"/>

  <text x="88" y="92" font-family="'Poppins', sans-serif" font-size="13" font-weight="600" fill="#EDEAE6">Pass-ta-key</text>
  <text x="88" y="110" font-family="'Share Tech Mono', monospace" font-size="10" fill="#8A7A5A">REGLA 1</text>
  <text x="290" y="92" font-family="'Share Tech Mono', monospace" font-size="11" fill="rgba(237,234,230,.80)">Lectura del enclave y la LevelDB</text>
  <text x="540" y="92" font-family="'Share Tech Mono', monospace" font-size="11" fill="rgba(237,234,230,.80)">Security 4663</text>
  <circle cx="696" cy="88" r="5" fill="none" stroke="#8A7A5A" stroke-width="1.5"/>
  <text x="712" y="92" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">AUDITORÍA + SACL</text>
  <line x1="84" y1="128" x2="870" y2="128" stroke="rgba(237,234,230,.08)" stroke-width="1"/>

  <text x="88" y="162" font-family="'Poppins', sans-serif" font-size="13" font-weight="600" fill="#EDEAE6">Silver Pass-ta-key</text>
  <text x="88" y="180" font-family="'Share Tech Mono', monospace" font-size="10" fill="#8A7A5A">REGLA 2</text>
  <text x="290" y="162" font-family="'Share Tech Mono', monospace" font-size="11" fill="rgba(237,234,230,.80)">Borrado del estado del enclave</text>
  <text x="540" y="162" font-family="'Share Tech Mono', monospace" font-size="11" fill="rgba(237,234,230,.80)">Sysmon 23/26</text>
  <circle cx="696" cy="158" r="5" fill="none" stroke="#8A7A5A" stroke-width="1.5"/>
  <text x="712" y="162" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">RUTA EN LA CONFIG</text>
  <line x1="84" y1="198" x2="870" y2="198" stroke="rgba(237,234,230,.08)" stroke-width="1"/>

  <text x="88" y="232" font-family="'Poppins', sans-serif" font-size="13" font-weight="600" fill="#EDEAE6">Golden Pass-ta-key</text>
  <text x="88" y="250" font-family="'Share Tech Mono', monospace" font-size="10" fill="#8A7A5A">REGLA 3</text>
  <text x="290" y="232" font-family="'Share Tech Mono', monospace" font-size="11" fill="rgba(237,234,230,.80)">Lectura de memoria de chrome.exe</text>
  <text x="540" y="232" font-family="'Share Tech Mono', monospace" font-size="11" fill="rgba(237,234,230,.80)">Sysmon 10</text>
  <circle cx="696" cy="228" r="5" fill="#8A7A5A"/>
  <text x="712" y="232" font-family="'Share Tech Mono', monospace" font-size="10" fill="#EDEAE6">DE SERIE</text>
  <line x1="84" y1="268" x2="870" y2="268" stroke="rgba(237,234,230,.28)" stroke-width="1"/>

  <circle cx="92" cy="298" r="5" fill="none" stroke="#8A7A5A" stroke-width="1.5"/>
  <text x="108" y="302" font-family="'Poppins', sans-serif" font-size="12" fill="rgba(237,234,230,.80)">Hay que habilitarlo antes: dos de los tres ataques no dejan rastro con la configuración por defecto.</text>
  <text x="88" y="340" font-family="'Share Tech Mono', monospace" font-size="10" fill="rgba(237,234,230,.56)">COBERTURA DE DETECCIÓN EN EL ENDPOINT · CHROME SOBRE WINDOWS</text>
</svg>
<figcaption>Lo que decide si una regla sirve no es la regla, es si la fuente existe. El círculo relleno marca la única señal disponible sin tocar nada; los dos huecos exigen trabajo previo de configuración.</figcaption>
</figure>

### Regla 1 — lectura de los ficheros de passkeys {#regla-lectura}

```yaml
title: Lectura del estado de passkeys de Chrome por un proceso ajeno al navegador
id: 95a71ddb-fca0-4d27-9b20-c3741d84ed5b
status: experimental
description: |
  Detecta accesos de lectura al estado del enclave de passkeys y a la base de datos
  de sincronización de Chrome desde procesos que no son el propio navegador. Es el
  primer movimiento de los ataques Pass-ta-key descritos por Unit 42.
  REQUISITO: auditoría de acceso a objetos activada y SACL sobre las rutas.
references:
  - https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/
  - https://attack.mitre.org/techniques/T1555/003/
author: Fray García
date: 2026/08/08
tags:
  - attack.credential-access
  - attack.t1555.003
logsource:
  product: windows
  service: security
detection:
  selection_lectura:
    EventID: 4663
    AccessMask: '0x1'
  objetivo_enclave:
    ObjectName|endswith: '\passkey_enclave_state'
  objetivo_sync:
    ObjectName|contains|all:
      - '\Google\Chrome\User Data\'
      - '\Sync Data\LevelDB'
  filter_navegador:
    ProcessName|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
  condition: selection_lectura and 1 of objetivo_* and not filter_navegador
falsepositives:
  - Herramientas de copia de seguridad y sincronización de perfiles
  - Antivirus y agentes EDR que escanean el perfil del navegador
  - Utilidades de migración de perfiles en despliegues corporativos
level: high
```

`AccessMask: '0x1'` es `ReadData`. Se puede ampliar a `0x80` (`ReadAttributes`) si se quiere cubrir
también el reconocimiento previo, a costa de bastante más ruido.

### Regla 2 — borrado del estado del enclave {#regla-borrado}

Esta es la que yo pondría primero si solo pudiera desplegar una. El borrado del fichero de estado no
es un efecto colateral: es el disparador deliberado del re-onboarding que el ataque *Silver*
necesita.

```yaml
title: Borrado del estado del enclave de passkeys de Chrome
id: 54e63fff-016e-4e58-b0cd-f35593d1f3f4
status: experimental
description: |
  Detecta el borrado del fichero passkey_enclave_state, que fuerza a Chrome a
  re-registrar el dispositivo. Durante ese re-onboarding existe la ventana
  uv_key_pending que el ataque Silver Pass-ta-key usa para registrar una clave
  de verificación de usuario controlada por el atacante.
references:
  - https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/
  - https://attack.mitre.org/techniques/T1555/003/
author: Fray García
date: 2026/08/08
tags:
  - attack.credential-access
  - attack.defense-evasion
  - attack.t1555.003
logsource:
  category: file_delete
  product: windows
detection:
  selection:
    TargetFilename|endswith: '\passkey_enclave_state'
  filter_navegador:
    Image|endswith: '\chrome.exe'
  condition: selection and not filter_navegador
falsepositives:
  - Reinstalación o reparación de Chrome
  - Limpiadores de perfil ejecutados por el usuario
  - Restauración de imagen del equipo
level: high
```

Cubre los Event ID 23 y 26 de Sysmon (`FileDelete` y `FileDeleteDetected`), siempre que la ruta esté
incluida en la configuración de Sysmon: el borrado de ficheros se filtra por directorio y el perfil
de Chrome no entra en las plantillas habituales.

Vale la pena emparejarla con una regla de Event ID 11 sobre el mismo fichero: **borrado seguido de
recreación en cuestión de segundos** es la firma del ciclo completo, y esa correlación tiene mucho
menos falso positivo que cualquiera de las dos señales por separado.

### Regla 3 — lectura de la memoria de Chrome {#regla-memoria}

```yaml
title: Acceso de lectura a la memoria de Chrome desde un proceso no confiable
id: d6e6222a-561b-4787-bd6c-ebf501d1733e
status: experimental
description: |
  Detecta procesos que abren chrome.exe solicitando PROCESS_VM_READ. Es la vía por
  la que el ataque Golden Pass-ta-key extrae el Security Domain Secret de 32 bytes
  que descifra todas las passkeys sincronizadas de la cuenta. La misma señal cubre
  el robo clásico de cookies y credenciales del navegador.
references:
  - https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/
  - https://attack.mitre.org/techniques/T1555/003/
author: Fray García
date: 2026/08/08
tags:
  - attack.credential-access
  - attack.t1555.003
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\chrome.exe'
    GrantedAccess:
      - '0x1410'
      - '0x1010'
      - '0x1418'
      - '0x143a'
      - '0x1F3FFF'
      - '0x1FFFFF'
  filter_propio:
    SourceImage|endswith: '\chrome.exe'
  filter_seguridad:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\MsSense.exe'
      - '\SenseIR.exe'
  condition: selection and not 1 of filter_*
falsepositives:
  - Agentes EDR y antivirus no incluidos en el filtro
  - Herramientas de depuración y perfilado
  - Software de accesibilidad y de automatización de escritorio
level: medium
```

Nivel `medium` a propósito: sin depurar contra el parque real, esta regla genera ruido. Pero es la
única de las tres que funciona con una instalación de Sysmon estándar, sin tocar la auditoría de
Windows.

### Qué hacer con los falsos positivos {#falsos-positivos}

Las tres reglas comparten el mismo patrón de afinado, y no hay atajo: ejecutarlas primero en modo
observación una o dos semanas, sacar la lista de procesos de origen y decidir uno a uno. En un parque
gestionado la lista es corta y aburrida — el EDR, la copia de seguridad, el agente de inventario — y
lo que quede fuera de esa lista, precisamente por ser corta, es lo que merece mirarse.

El orden que yo seguiría, de más a menos rentable:

1. **Regla 2** (borrado). Poco volumen, señal muy específica, no requiere tocar la auditoría.
2. **Regla 3** (memoria). Funciona ya, y de paso cubre el robo de cookies, que es un problema mucho
   más frecuente que este.
3. **Regla 1** (lectura). La más valiosa conceptualmente y la más cara: sin SACL no existe, y la SACL
   sobre un perfil de navegador hay que dimensionarla antes de desplegarla en producción.

### Cómo se evaden estas tres reglas {#evasion}

Escribir la regla y no preguntarse cómo se esquiva es la mitad del trabajo. Las tres tienen un hueco
identificable, y en los tres casos la salida es la misma familia de técnica.

**La Regla 1 depende de dónde pusiste la SACL.** La auditoría cubre las rutas que enumeraste, no el
contenido. Copiar el directorio del perfil a `%TEMP%` y leer la copia deja el original intacto: la
lectura auditada no llega a producirse. Cubrirlo pasa por vigilar también la copia masiva del perfil
del navegador — Sysmon Event ID 11 sobre creaciones que reproducen la estructura de `User Data`.

**La Regla 2 solo mira el borrado.** Chrome vuelve a registrarse igual si el fichero está corrupto o
truncado, y truncar no genera evento de borrado. Por eso insistía antes en emparejarla con el
Event ID 11 sobre el mismo fichero: la modificación en el sitio sí queda, el borrado no es
imprescindible para el atacante.

**La Regla 3 se evade desde dentro.** El filtro `filter_propio` excluye a `chrome.exe` como origen,
que es lo que la hace desplegable y a la vez su punto ciego: código inyectado en el propio proceso de
Chrome lee esa memoria sin que haya ningún `ProcessAccess` entre procesos distintos. La detección
secundaria no es de acceso a memoria sino de inyección — Sysmon Event ID 8 (`CreateRemoteThread`) y
Event ID 7 sobre módulos no firmados cargados en el navegador.

El patrón se repite: cada una de las tres se esquiva moviéndose una capa más adentro, y la respuesta
siempre es una regla de comportamiento genérico, no una más específica. Es un argumento a favor de
desplegar las tres a la vez en lugar de elegir la mejor.

## Qué se traslada a un despliegue corporativo {#corporativo}

Si administras identidad y estás empujando passkeys — que hay que seguir empujando, esto no es un
argumento para volver a las contraseñas — hay tres lecturas prácticas.

**No todas las passkeys son iguales.** Una passkey ligada a hardware y una sincronizada tienen el
mismo aspecto en el panel de administración y modelos de amenaza distintos. Para las cuentas que
importan de verdad, la sincronizada no es el nivel adecuado.

**La verificación de usuario hay que exigirla en los dos lados.** Pedir `userVerification =
required` en el registro no sirve de nada si luego no se valida el flag *UV* en la respuesta. Eso es
trabajo del servicio, no del cliente, y es donde falla la cadena en el primer ataque.

**El endpoint sigue siendo el eslabón.** Este es el patrón que se repite: mueves el secreto a la
nube, y el atacante deja de robar el secreto para robar la sesión o la identidad del dispositivo que
lo pide. El equivalente en AWS es idéntico — no roban tu clave de acceso, roban credenciales
temporales del servicio de metadatos. Si el puesto de trabajo está comprometido, la criptografía de
la capa de autenticación deja de ser el problema.

## Conclusiones {#conclusiones}

1. Para passkeys sincronizadas, el TPM protege la identidad del dispositivo, no la clave de la
   passkey. Son dos cosas distintas y la publicidad las trata como una.
2. La detección del lado del servicio está desactivada de facto por el contador de firmas constante.
   Todo lo que quede está en el endpoint.
3. De los tres ataques, dos no dejan rastro en una instalación de Sysmon por defecto. La detección
   más barata y específica es el borrado del estado del enclave; la más completa exige activar
   auditoría de acceso a objetos con SACL.
4. Nada de esto es un argumento contra las passkeys. Es un argumento contra el «no hay nada que
   robar», que era falso en cuanto la clave se sincroniza.

## Limitaciones {#limitaciones}

Esto es análisis defensivo sobre investigación ajena, no investigación propia. Los tres ataques, las
rutas, las llamadas a CNG y los nombres de los comandos del autenticador en la nube salen de la
publicación de Unit 42 firmada por Arie Olshtein; yo no he hecho ingeniería inversa de Chrome ni he
reproducido ninguno de los ataques.

Lo que aporto son las reglas, y hay que decir con qué garantía: **están razonadas a partir de esas
rutas y APIs, no validadas contra el ataque real ni contra telemetría capturada.** No he ejecutado el
ataque en un laboratorio con Sysmon delante para comprobar que disparan, ni he medido su tasa de
falso positivo en un parque real. Son un punto de partida para probar en modo observación, no reglas
listas para producción.

Dos precisiones más sobre las rutas. La de la base de datos de sincronización aparece completa en la
publicación original; la de `passkey_enclave_state` no, y por eso las reglas coinciden por nombre de
fichero y no por ruta absoluta — que además es lo correcto, porque el nombre del perfil varía. Y todo
lo anterior es Chrome sobre Windows: no he comprobado el comportamiento en macOS, en Linux ni en
otros navegadores basados en Chromium, aunque el modelo de sincronización invite a pensar que hay
algo parecido.

## Referencias {#referencias}

<ol class="refs">
<li><a href="https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/">Pass the Passkey: Attacking Synced Passkeys</a>. Arie Olshtein, Unit 42 — Palo Alto Networks, 3 de agosto de 2026.</li>
<li><a href="https://www.w3.org/TR/webauthn-3/">Web Authentication: An API for accessing Public Key Credentials, Level 3</a>. W3C.</li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system">Audit File System</a>. Microsoft Learn — configuración de la auditoría de acceso a objetos y SACL.</li>
<li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon">Sysmon</a>. Microsoft Sysinternals — referencia de Event ID.</li>
<li><a href="https://sigmahq.io/">SigmaHQ</a>. Especificación del formato de reglas.</li>
</ol>
