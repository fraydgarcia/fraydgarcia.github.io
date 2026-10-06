---
layout: research
title: "FortiMail: el correo sale por el archivado"
date: 2026-10-06
author: "Fray García"
image: "/assets/img/og/fortimail-archivado.png"
lead: "CVE-2026-104286 es un path traversal sin autenticar en el portal IBE de FortiMail, explotado antes de que hubiera parche. La parte llamativa es la persistencia con ld.so.preload. La parte útil para detectar es otra: una línea de log en la que el atacante da de alta una cuenta de archivado que manda el correo a su servidor."
description: "Análisis defensivo de CVE-2026-104286 en FortiMail: qué es el portal IBE, la cadena de explotación según los indicadores de Fortinet, cuatro reglas Sigma construidas sobre las líneas de log publicadas y por qué la mitigación recomendada choca con para qué sirve el producto."
stack: "CVE-2026-104286 · FortiMail · CWE-22 · CWE-158 · Sigma · Syslog · CISA KEV"
toc:
  - title: "Introducción"
    id: introduccion
  - title: "El IBE está expuesto por diseño"
    id: ibe
  - title: "El fallo, las versiones y el calendario"
    id: el-fallo
    children:
      - title: "Versiones afectadas"
        id: versiones
      - title: "Tres días"
        id: calendario
  - title: "Qué hace el atacante después"
    id: post-explotacion
  - title: "Detección"
    id: deteccion
    children:
      - title: "Regla 1 — cuenta de archivado con destino remoto"
        id: regla-archivado
      - title: "Regla 2 — cron como root sobre /migadmin"
        id: regla-cron
      - title: "Regla 3 — excepción Base64 en el descifrador IBE"
        id: regla-ibe
      - title: "Regla 4 — POST con traversal hacia /ibe"
        id: regla-proxy
      - title: "Indicadores para buscar hacia atrás"
        id: indicadores
      - title: "Cómo se evaden estas reglas"
        id: evasion
  - title: "La mitigación que no encaja con el producto"
    id: mitigacion
  - title: "Conclusiones"
    id: conclusiones
  - title: "Limitaciones"
    id: limitaciones
  - title: "Referencias"
    id: referencias
---

## Introducción {#introduccion}

El 1 de octubre Fortinet publicó **FG-IR-26-175**: un path traversal combinado con un NULL byte
(CWE-22 y CWE-158) que permite a un atacante sin autenticar **escribir ficheros arbitrarios** en
FortiMail con una petición HTTP o HTTPS manipulada. CVSS 9.8. El mismo día CISA lo metió en el
catálogo KEV, porque ya se estaba explotando. Lo encontró el propio equipo de seguridad de producto
de Fortinet, no un investigador externo, y cuando se publicó no había ninguna versión corregida
disponible.

Casi toda la cobertura se ha quedado en la persistencia: binarios troyanizados y un
`ld.so.preload` que carga una librería maliciosa en cada proceso del appliance. Es lo más
llamativo, y para quien defiende es lo menos útil, porque casi nadie tiene visibilidad del sistema
de ficheros de un appliance cerrado.

Lo que sí se puede ver está en el propio aviso. Fortinet publicó las **líneas de log** que deja el
ataque, y una de ellas cuenta más que todos los ficheros juntos: el atacante da de alta una
**cuenta de archivado** con destino remoto, apuntando a una de las IP de los indicadores. Es decir,
usa una función legítima del producto para sacar el correo.

Este artículo sale de esas líneas: qué significan, cuatro reglas Sigma para detectarlas y por qué
la mitigación recomendada choca con aquello para lo que existe el IBE.

## El IBE está expuesto por diseño {#ibe}

**IBE** (*Identity-Based Encryption*) es la función de FortiMail para mandar correo cifrado a
destinatarios externos que no tienen ningún cliente especial. El destinatario recibe un aviso,
entra en un portal web servido por el propio FortiMail, se registra o se autentica y lee el mensaje
allí.

Ese detalle cambia el modelo de amenaza. Un panel de administración puede vivir en una red de
gestión. **Un portal pensado para que lo usen personas de fuera de la empresa tiene que estar
publicado en Internet**, porque si no, no sirve. Las organizaciones que lo usan suelen ser las que
más motivos tienen para cifrar correo: sanidad, banca, despachos, administración.

> El IBE no está expuesto por un descuido de configuración. Está expuesto porque es su trabajo.

## El fallo, las versiones y el calendario {#el-fallo}

El fallo está en el manejo de rutas de las peticiones que llegan al IBE. Una secuencia `../` saca
la escritura del directorio previsto. El NULL byte resuelve el otro problema del atacante: la
comprobación de la ruta y la escritura en disco no interpretan la cadena igual. La validación corta
en el `0x00` y da por buena una ruta inocente; la escritura sigue leyendo y llega donde el atacante
quería.

Fortinet no ha publicado la petición exacta y yo no la he reproducido. Lo que sigue se basa en lo
que el fabricante sí ha publicado: el componente, el efecto y lo que queda después.

| Campo | Valor | Lectura |
|---|---|---|
| AV — vector de ataque | N (red) | alcanzable desde Internet, y el IBE está ahí por diseño |
| AC — complejidad | L (baja) | sin condiciones de carrera ni configuración rara |
| PR — privilegios | N (ninguno) | sin autenticar |
| UI — interacción | N (ninguna) | nadie tiene que hacer clic |
| S — alcance | U (sin cambio) | el impacto se queda en el appliance… sobre el papel |
| **C / I / A** | **H / H / H** | escritura de ficheros como root: todo |

La fila del alcance es la que menos me convence. CVSS puntúa el appliance, pero un gateway de
correo tiene acceso al correo de toda la organización y, en la mayoría de despliegues, una conexión
LDAP con el directorio. Ya hablé del [límite del CVSS]({{ '/research/cve-2026-56164-un-53-que-tambien-es-un-98/' | relative_url }})
con otro caso; aquí vuelve a aparecer.

### Versiones afectadas {#versiones}

| Rama | Vulnerables | Corregida en | Nota |
|---|---|---|---|
| 8.0 | 8.0.0 – 8.0.1 | 8.0.2 | |
| 7.6 | 7.6.0 – 7.6.6 | 7.6.7 | |
| 7.4 | 7.4.0 – 7.4.8 | 7.4.9 | |
| 7.2 | 7.2.0 – 7.2.9 | — | **sin corrección en la rama**: hay que migrar a 7.4 o superior |

Los rangos son inclusivos: 7.6.6 y 7.4.8 **son vulnerables**. Lo digo porque he visto resúmenes que
escriben `< 7.6.6` y dejan fuera justo la última versión afectada de cada rama.

La rama 7.2 merece una línea aparte. No va a recibir parche: la salida es un cambio de rama, que en
un gateway de correo en producción no se hace en una tarde. Quien esté en 7.2 vive con la
mitigación más tiempo que nadie.

### Tres días {#calendario}

<figure class="diagrama">
<ol class="cronologia">
<li class="hito"><span class="crono-punto"></span><span class="crono-fecha">1 oct</span><span class="crono-titulo">Aviso y alta en KEV</span><span class="crono-nota">Ya se estaba explotando</span></li>
<li><span class="crono-punto"></span><span class="crono-fecha">2 oct</span><span class="crono-titulo">Sin versiones corregidas</span><span class="crono-nota">Solo queda la mitigación</span></li>
<li class="hito"><span class="crono-punto"></span><span class="crono-fecha">4 oct</span><span class="crono-titulo">Vence el plazo de CISA</span><span class="crono-nota">Tres días desde el alta</span></li>
<li><span class="crono-punto"></span><span class="crono-fecha">5 oct</span><span class="crono-titulo">Aviso actualizado</span><span class="crono-nota">Fortinet publica la solución</span></li>
<li class="crono-tramo">El plazo de remediación terminó antes de que existiera el parche.</li>
</ol>
<figcaption>Puntos rellenos: hitos de CISA y del aviso. Puntos huecos: el estado del parche. Entre el alta en KEV y la fecha límite solo había una opción real, la mitigación.</figcaption>
</figure>

Es el tramo de **tres días** que describí en [el plazo de CISA pasó de 21 días a 3]({{ '/research/el-plazo-de-cisa-paso-de-21-dias-a-3/' | relative_url }}),
y es un buen ejemplo de lo que significa en la práctica: cuando el plazo vence antes que el parche,
la directiva no está pidiendo parchear. Está pidiendo apagar la función o aislarla.

## Qué hace el atacante después {#post-explotacion}

Fortinet y Truesec publicaron los ficheros que el atacante deja en el appliance. Ordenados por lo
que hacen:

| Fichero | Cambio | Para qué sirve |
|---|---|---|
| `/data/lib/liblog.so` | añadido | la librería que se inyecta en los procesos |
| `/data/etc/ld.so.preload` | añadido | hace que el enlazador dinámico cargue esa librería en **cada** proceso que arranque |
| `/data/bin/webconsole` | añadido | binario troyanizado |
| `/data/bin/mailservice` | añadido | binario troyanizado |
| `/bin/smit` | modificado | binario del sistema alterado |
| `/data/etc/httpd.conf` | modificado | configuración del servidor web del appliance |
| `/data/migadmin.tar.gz` | modificado | paquete que reaparece en la tarea de cron |

`ld.so.preload` es persistencia a nivel de host: no depende de que un servicio concreto siga
vulnerable, porque cualquier proceso nuevo carga la librería. Aplicar el parche después no limpia
nada. **Un FortiMail comprometido antes del parche sigue comprometido después.**

El resto de la cadena se reconstruye con las líneas de log del aviso, y ahí aparece lo que nadie
estaba mirando:

<figure class="diagrama">
<div class="cadena-head"><span>Paso</span><span>Qué hace el atacante</span><span>Qué queda en los logs</span></div>
<ol class="cadena">
<li><span class="cadena-n">01</span><div class="cadena-que"><strong>POST al IBE con <code>../</code> y NULL byte</strong><span>Sin autenticar, desde Internet</span></div><div class="cadena-log">Excepción en el log de cifrado</div></li>
<li><span class="cadena-n">02</span><div class="cadena-que"><strong>Escritura de ficheros como root</strong><span><code>liblog.so</code>, <code>webconsole</code>, <code>mailservice</code></span></div><div class="cadena-log sin-rastro">Nada en los logs</div></li>
<li><span class="cadena-n">03</span><div class="cadena-que"><strong>Persistencia con <code>ld.so.preload</code></strong><span>La librería entra en cada proceso</span></div><div class="cadena-log sin-rastro">Nada en los logs</div></li>
<li><span class="cadena-n">04</span><div class="cadena-que"><strong>Tarea de cron como root</strong><span><code>/bin/sh -c 'O=/migadmin …'</code></span></div><div class="cadena-log">Evento de sistema: cron como root</div></li>
<li><span class="cadena-n">05</span><div class="cadena-que"><strong>Cuenta de archivado con destino remoto</strong><span><code>remote-ip[79.141.169.187]</code> → <code>/uploads</code></span></div><div class="cadena-log">Evento de configuración: alta de la cuenta</div></li>
</ol>
<figcaption>Lo que pasa dentro del appliance no deja rastro; lo que el atacante hace con el producto, sí. Punto relleno: el paso deja una línea en los logs de FortiMail que Fortinet ha publicado. Punto hueco: solo se ve con acceso al sistema de ficheros del appliance. Cadena reconstruida a partir de los indicadores de FG-IR-26-175.</figcaption>
</figure>

Esta es la línea del paso 5 que publica el aviso, partida en varias líneas para que se lea:

```text
type=kevent subtype=config pri=information user=admin ui=cli
module=unknown submodule=unknown
msg="Added 'archive234' to 'archive account' :
  rotation-size[50]rotation-time[1]rotation-hour[14]
  destination[remote]remote-ip[79.141.169.187]
  remote-username[archive234]remote-password[***]
  remote-directory[/uploads] (user: admin, from: cli)"
```

El archivado de FortiMail existe para guardar copia del correo por motivos legales o de
cumplimiento, y puede enviarla a un servidor remoto. El atacante crea una cuenta de archivado que
rota cada hora (`rotation-time[1]`) y deposita lo archivado en `/uploads` de una IP suya. No
necesita su propio canal de exfiltración, porque el producto ya trae uno.

Es una inferencia razonable a partir de la línea, no algo que Fortinet diga con esas palabras.
Pero si el objetivo fuera solo persistir, esa cuenta sobraría.

## Detección {#deteccion}

Una condición previa que decide todo lo demás: **estas reglas solo funcionan si los logs de
FortiMail salen del appliance**. Muchos equipos tratan los appliances de seguridad perimetral como
cajas que ya se protegen solas y no reenvían sus eventos al SIEM. En este caso, además, el
atacante es root: lo que se quede en el disco local lo puede borrar.

Las cuatro reglas usan los campos `key=value` del syslog de FortiMail (`type`, `subtype`, `ui`,
`msg`). Sigma no tiene un `logsource` oficial para FortiMail, así que el que uso es propio y el
mapeo de campos depende de cómo los parsee cada SIEM.

| Regla | Paso | Fuente | Fiabilidad | Ruido esperado |
|---|---|---|---|---|
| 1 — archivado remoto | 05 | evento `config` | alta | muy bajo: un alta de archivado es un cambio raro |
| 2 — cron sobre /migadmin | 04 | evento `system` | alta | casi nulo |
| 3 — excepción Base64 en IBE | 01 | log de cifrado | media | peticiones IBE malformadas legítimas |
| 4 — POST con traversal a /ibe | 01 | proxy o WAF delante | media | escáneres; solo ve la URI |

### Regla 1 — cuenta de archivado con destino remoto {#regla-archivado}

La que pondría primero. Detecta el propósito del atacante, no su técnica, y por eso sobrevive a
que cambie el exploit.

```yaml
title: Alta de cuenta de archivado con destino remoto en FortiMail
id: 306995a9-7279-4b16-ab5c-7dc8cc4dc2ab
status: experimental
description: |
  Detecta la creación de una cuenta de archivado de FortiMail que envía el correo a
  un servidor remoto. En la explotación de CVE-2026-104286 el atacante configura el
  archivado hacia una IP propia para llevarse el correo con una función del producto.
references:
  - https://www.fortiguard.com/psirt/FG-IR-26-175
author: Fray García
date: 2026-10-06
tags:
  - attack.collection
  - attack.t1114
  - attack.exfiltration
  - attack.t1020
  - cve.2026-104286
logsource:
  product: fortimail
  service: event
detection:
  selection:
    type: 'kevent'
    subtype: 'config'
    msg|contains|all:
      - "to 'archive account'"
      - 'destination[remote]'
  condition: selection
falsepositives:
  - Alta legítima de archivado remoto, que debería coincidir con un cambio aprobado
level: high
```

Si la organización ya archiva en remoto, la versión útil es la contraria: alertar cuando la
`remote-ip` **no** esté en la lista de servidores de archivado conocidos. Con ese filtro la regla
pasa a `critical`.

### Regla 2 — cron como root sobre /migadmin {#regla-cron}

```yaml
title: Ejecución por cron como root con referencia a /migadmin en FortiMail
id: 5c370a2c-6d0f-4b82-b43e-1ffadc9a9fb6
status: experimental
description: |
  Detecta una tarea de cron ejecutada como root que referencia /migadmin, indicador
  publicado por Fortinet para la post-explotación de CVE-2026-104286.
references:
  - https://www.fortiguard.com/psirt/FG-IR-26-175
author: Fray García
date: 2026-10-06
tags:
  - attack.persistence
  - attack.execution
  - attack.t1053.003
  - cve.2026-104286
logsource:
  product: fortimail
  service: event
detection:
  selection:
    type: 'event'
    subtype: 'system'
    ui: 'cron'
    msg|contains|all:
      - '(root) CMD'
      - '/migadmin'
  condition: selection
falsepositives:
  - No se conocen
level: critical
```

Depende de una sola cadena y por eso es frágil (lo veo abajo, en evasión). La versión general es
más valiosa a medio plazo: **cualquier** `(root) CMD` con `/bin/sh -c` que no esté en la línea base
del appliance. Un FortiMail tiene pocas tareas programadas, y siempre las mismas.

### Regla 3 — excepción Base64 en el descifrador IBE {#regla-ibe}

El aviso incluye una excepción del componente que descifra los mensajes IBE. El carácter que la
provoca, `0x2a`, es un asterisco, y aparece en la posición 0 de algo que debería ser Base64.

```yaml
title: Excepción de decodificación Base64 en el descifrador IBE de FortiMail
id: 3dcd19f0-b8da-48ec-9031-fab63d674842
status: experimental
description: |
  Detecta la excepción BufferException del componente DecrypterMediaIn del IBE con
  un error de Base64 en la posición 0, publicada por Fortinet como rastro de los
  intentos de explotación de CVE-2026-104286.
references:
  - https://www.fortiguard.com/psirt/FG-IR-26-175
author: Fray García
date: 2026-10-06
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-104286
logsource:
  product: fortimail
  service: encryption
detection:
  selection:
    msg|contains|all:
      - 'IBE::DecrypterMediaIn'
      - 'BufferException'
      - 'Invalid Base64 Encoding at pos 0'
  condition: selection
falsepositives:
  - Peticiones IBE malformadas por clientes o enlaces corruptos
level: medium
```

Nivel `medium` a propósito: no sé con qué frecuencia aparece esta excepción en un IBE sano. Primero
hay que medirla. Si en la línea base sale cero veces, sube de nivel sola.

### Regla 4 — POST con traversal hacia /ibe {#regla-proxy}

Entre las mitigaciones, Fortinet propone bloquear las peticiones `POST` hacia rutas `/ibe` que
contengan `../`. Eso indica dónde mirar si hay un proxy inverso o un WAF delante del FortiMail.

```yaml
title: Petición POST con path traversal hacia el IBE de FortiMail
id: 00e7f635-408e-4090-bea5-6850aab7d738
status: experimental
description: |
  Detecta peticiones POST hacia rutas /ibe que contienen secuencias de path traversal
  o un NULL byte codificado, el patrón de explotación de CVE-2026-104286. Pensada para
  logs de un proxy inverso o WAF situado delante del FortiMail.
references:
  - https://www.fortiguard.com/psirt/FG-IR-26-175
author: Fray García
date: 2026-10-06
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-104286
logsource:
  category: webserver
detection:
  selection_ibe:
    cs-method: 'POST'
    cs-uri-stem|contains: '/ibe'
  selection_traversal:
    - cs-uri-stem|contains:
        - '../'
        - '..%2f'
        - '%2e%2e'
    - cs-uri-query|contains:
        - '../'
        - '..%2f'
        - '%2e%2e'
        - '%00'
  condition: all of selection_*
falsepositives:
  - Escáneres de vulnerabilidades autorizados contra el portal IBE
level: high
```

Tiene un límite serio: un log de acceso registra la URI, no el cuerpo. Si el traversal viaja en el
cuerpo del `POST`, esta regla no lo ve y solo lo detecta un WAF que inspeccione el cuerpo. La dejo
porque es barata y caza a quien no se molesta en esconderlo.

### Indicadores para buscar hacia atrás {#indicadores}

El 1 de octubre la explotación ya estaba en marcha, así que la búsqueda tiene que mirar hacia atrás.
Estos son los indicadores publicados:

| Tipo | Indicador | Dónde buscarlo |
|---|---|---|
| IP | `79.141.169.187` | firewall perimetral, conexiones salientes del FortiMail, `remote-ip` del archivado |
| IP | `45.129.0.192` | firewall perimetral, logs del proxy |
| SHA-256 | `8953ec7960b09f544a880b072ad4e6cfda7a8303f486251d3478dcfdfbac23b6` | `ld.so.preload` en copias o imágenes del appliance |
| Fichero | `/data/etc/ld.so.preload` | su sola presencia en un FortiMail ya es anómala |
| Cuenta | `archive234` en la configuración de archivado | copia de configuración |
| Log | `Internal user … failed to log in.` | evento de autenticación; útil solo correlado con lo anterior |

En el firewall, **la conexión saliente desde el FortiMail** hacia la primera IP vale más que la
entrante. La entrante dice que alguien lo intentó. La saliente dice que el archivado ya estaba
funcionando.

Las IP caducan rápido. Sirven para la búsqueda retrospectiva de esta semana, no como bloqueo
permanente.

### Cómo se evaden estas reglas {#evasion}

**La Regla 1 no ve otras vías de salida.** Si el siguiente atacante saca el correo con los
binarios troyanizados en lugar del archivado, no se da de alta ninguna cuenta. Tampoco protege
contra que cambie la IP. La regla vigila un mecanismo, no al actor, y por eso conviene acompañarla
con la vigilancia de conexiones salientes del FortiMail hacia destinos nuevos.

**La Regla 2 depende de una cadena.** Basta con renombrar `/migadmin` para que no dispare. La
versión basada en línea base que propongo arriba no tiene ese problema.

**Las Reglas 3 y 4 dependen del payload.** Otra codificación del NULL byte, el traversal en el
cuerpo o una doble codificación de URL las dejan atrás. Son reglas de intento, no de compromiso.

**Las cuatro dependen de que el log salga.** Un atacante con root en el appliance puede dejar de
enviar syslog o borrar lo local. La ausencia de eventos de un FortiMail que normalmente habla mucho
es, en sí misma, una alerta que vale la pena tener.

## La mitigación que no encaja con el producto {#mitigacion}

| Opción | Qué hace | Coste | Qué deja fuera |
|---|---|---|---|
| Actualizar a 8.0.2, 7.6.7 o 7.4.9 | corrige el fallo | ventana de mantenimiento; en 7.2, un cambio de rama | **no limpia un compromiso previo** |
| Desactivar el IBE | elimina la superficie | los destinatarios externos dejan de poder leer el correo cifrado | nada, mientras siga apagado |
| Restringir el acceso a redes de confianza | reduce quién llega al portal | el IBE deja de servir a los externos | contradice el propósito del IBE |
| Bloquear en el WAF los `POST` con `../` hacia `/ibe` | corta el patrón conocido | requiere un WAF que inspeccione el cuerpo | variantes de codificación |

El comando para desactivar el IBE, según el aviso:

```text
config system encryption ibe
    set status disable
end
```

La tercera fila es la que no me cuadra. Restringir el acceso a redes privadas es el consejo
estándar para un panel de administración, y Fortinet lo incluye. Aplicado al IBE equivale a
apagarlo, porque sus usuarios están fuera por definición. En la práctica hay dos opciones honestas:
apagar el IBE hasta parchear o mantenerlo con un WAF delante sabiendo lo que el WAF no cubre.

Y una cosa más: actualizar cierra la puerta, pero no echa a quien ya entró. Antes de dar por
cerrado un FortiMail que estuvo expuesto antes del parche, hay que pasar por
los indicadores de arriba, y en particular revisar la configuración de archivado.

## Conclusiones {#conclusiones}

1. El IBE está publicado en Internet por diseño. Un fallo sin autenticar en ese portal tiene la
   superficie máxima, y la mitigación de «restringir a redes de confianza» equivale a apagarlo.
2. La persistencia con `ld.so.preload` es lo más llamativo y lo menos detectable: no deja rastro en
   los logs del appliance.
3. Lo detectable es lo que el atacante hace **con** el producto: la tarea de cron y, sobre todo, la
   cuenta de archivado con destino remoto. Esa regla detecta el propósito y sobrevive a cambios en
   el exploit.
4. Nada de esto funciona si los logs del FortiMail no llegan al SIEM. Ese es el primer cambio, antes
   que cualquier regla.
5. Parchear no limpia. Un appliance expuesto durante la ventana hay que revisarlo como posiblemente
   comprometido.

## Limitaciones {#limitaciones}

Esto es análisis defensivo sobre fuentes públicas, no investigación propia. No tengo acceso a un
FortiMail ni he visto el exploit. Las versiones, los ficheros, las IP y las líneas de log salen del
aviso FG-IR-26-175 de Fortinet; el hash de `ld.so.preload` sale del análisis de Truesec. No he
encontrado ningún PoC público verificable, y los repositorios que se anuncian como tal piden
contacto privado para entregar el exploit, un patrón que conviene tratar como sospechoso.

Las reglas están **construidas sobre las líneas de log publicadas, no validadas contra telemetría
real**. Lo que sí he comprobado: las cuatro pasan `sigma check` (sigma-cli 3.1.0) sin errores ni
avisos y se convierten a consulta Lucene, y las reglas 1, 2 y 3 coinciden con las líneas de ejemplo
del aviso de Fortinet. La regla 4 no tiene un log de proxy publicado contra el que probarla. Los nombres de campo (`type`, `subtype`, `ui`, `msg`) siguen el formato `key=value` del
syslog de FortiMail, pero el mapeo exacto depende de cómo los parsee cada SIEM, y el `logsource`
de FortiMail no es un estándar de Sigma. Hay que probarlas en modo observación antes de
desplegarlas.

Sobre el parche: a 2 de octubre las versiones corregidas no estaban publicadas, y el aviso se
actualizó el 5 de octubre con la solución. Conviene confirmar en el portal de soporte de Fortinet
que la versión de cada rama ya está disponible antes de planificar la actualización.

La lectura del archivado como canal de exfiltración es una inferencia mía a partir de una línea de
log. Es la explicación más directa, pero Fortinet no la describe así.

## Referencias {#referencias}

<ol class="refs">
<li><a href="https://www.fortiguard.com/psirt/FG-IR-26-175">FG-IR-26-175: FortiMail path traversal</a>. Fortinet PSIRT, 1 de octubre de 2026, actualizado el 5 de octubre.</li>
<li><a href="https://www.truesec.com/hub/blog/cve-2026-104286-fortimail-path-traversal-vulnerability-actively-exploited">CVE-2026-104286 FortiMail Path Traversal Vulnerability Actively Exploited</a>. Truesec.</li>
<li><a href="https://thehackernews.com/2026/10/critical-fortimail-zero-day-flaw.html">Critical FortiMail zero-day flaw</a>. The Hacker News, octubre de 2026.</li>
<li><a href="https://www.helpnetsecurity.com/2026/10/02/fortinet-fortimail-vulnerability-cve-2026-104286/">Critical FortiMail zero-day exploited in the wild (CVE-2026-104286)</a>. Help Net Security, 2 de octubre de 2026.</li>
<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>. CISA.</li>
<li><a href="https://sigmahq.io/">SigmaHQ</a>. Especificación del formato de reglas.</li>
</ol>
