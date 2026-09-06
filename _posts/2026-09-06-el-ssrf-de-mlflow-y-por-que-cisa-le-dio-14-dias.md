---
layout: research
title: "El SSRF de MLflow y por qué CISA le dio 14 días y no 3"
date: 2026-09-06
author: "Fray García"
lead: "CVE-2026-64849 es un 9.3 que no ejecuta código: lee la respuesta del endpoint de metadatos y se lleva las credenciales de la instancia. El plazo que le puso CISA — 14 días, no 3 — lo describe mejor que la nota de prensa."
description: "Análisis de CVE-2026-64849: la cadena SSRF en los webhooks de MLflow, por qué el objetivo es 169.254.169.254, y por qué el catálogo KEV le asignó un plazo de 14 días bajo BOD 26-04 en lugar de los 3 del tramo peor."
stack: "MLflow · CWE-918 · IMDSv2 · CISA KEV · BOD 26-04 · curl · jq"
toc:
  - title: "Introducción"
    id: introduccion
  - title: "La cadena"
    id: anatomia
    children:
      - title: "El endpoint sin autenticar"
        id: el-endpoint
      - title: "El bypass de la validación"
        id: el-bypass
      - title: "El objetivo: 169.254.169.254"
        id: el-objetivo
  - title: "Por qué el endpoint de metadatos es el premio"
    id: por-que-imds
  - title: "El 9.3 y el plazo"
    id: el-numero-y-el-plazo
    children:
      - title: "El vector, campo a campo"
        id: el-vector
      - title: "Catorce días, no tres"
        id: el-plazo
      - title: "Cómo sacarlo tú mismo"
        id: reproducir
  - title: "Qué se puede detectar"
    id: deteccion
  - title: "Qué se puede hacer"
    id: mitigacion
  - title: "Conclusiones"
    id: conclusiones
  - title: "Limitaciones"
    id: limitaciones
  - title: "Referencias"
    id: referencias
---

## Introducción {#introduccion}

El 17 de agosto de 2026 se asignó **CVE-2026-64849**, un fallo de tipo SSRF en el
servidor de MLflow con una puntuación CVSS de 9.3. Las primeras herramientas de
telemetría registraron escaneo indiscriminado buscando instancias expuestas
**a las pocas horas** de la asignación. El 19 de agosto CISA lo metió en su
catálogo de vulnerabilidades explotadas.

Nada de eso es raro para un 9.3 sobre un producto que la gente publica sin
autenticación. Lo que me hizo pararme fue el plazo: CISA le puso como fecha
límite el **2 de septiembre**. Catorce días. En [el análisis del catálogo
KEV]({{ '/research/el-plazo-de-cisa-paso-de-21-dias-a-3/' | relative_url }}) vimos
que desde junio de 2026 el tramo peor de la nueva directiva es de **tres días**, y
que ahí caen las cosas alcanzables desde Internet, automatizables y con impacto
total. Este CVE cumple los tres primeros requisitos de sobra. ¿Por qué 14 y no 3?

La respuesta corta, que adelanto aquí para quien no siga leyendo: porque
**CVE-2026-64849 roba credenciales, no toma el control del sistema**. Es un fallo
de confidencialidad, y el árbol de decisión de la directiva lo trata como lo que
es. Y hay un segundo detalle incómodo: el control que neutraliza esta clase
entera de ataques — IMDSv2 — lleva disponible en AWS desde 2019 y sigue siendo
opcional.

## La cadena {#anatomia}

MLflow es una plataforma para gestionar experimentos y modelos de machine
learning. El componente relevante aquí es el **registro de modelos** y, dentro de
él, los **webhooks**: notificaciones HTTP que MLflow envía a una URL cuando pasa
algo (un modelo nuevo, un cambio de etapa). Como cualquier sistema de webhooks,
trae un botón de "probar" que dispara una petición de prueba a la URL configurada.

### El endpoint sin autenticar {#el-endpoint}

El servidor de MLflow (`mlflow server`) **no trae autenticación en la
configuración por defecto**. Toda la API REST queda abierta a quien pueda
alcanzar el puerto. Entre esos endpoints está el de prueba de webhooks:

```
POST /api/2.0/mlflow/webhooks/{id}/test
```

Un atacante sin credenciales puede registrar un webhook y pedir que se pruebe. La
petición de prueba la hace **el servidor**, no el cliente. Ese es el primer
ingrediente de cualquier SSRF: una máquina de confianza que hace peticiones de
red en tu nombre.

### El bypass de la validación {#el-bypass}

MLflow no ignoraba el problema. En la versión 3.10.0 se añadió una función,
`_validate_webhook_url`, precisamente para impedir que los webhooks apuntaran a
destinos internos. El fallo es cómo valida:

- Comprueba el **nombre de host** de la URL, no la **dirección IP** a la que
  resuelve.
- La sesión HTTP que envía la petición **sigue las redirecciones** (un `302`) sin
  volver a validar el destino.
- El endpoint `/test` **devuelve el cuerpo de la respuesta** al que llamó.

Con esas tres piezas, la cadena es directa. El atacante registra un webhook que
apunta a un dominio propio con HTTPS — pasa la validación —, y ese dominio
responde con un `302` que redirige a `http://169.254.169.254/...`. MLflow sigue la
redirección, recibe la respuesta del servicio interno y **la refleja de vuelta**.
Es un SSRF de lectura completa, no a ciegas.

Hay una segunda vía por **DNS rebinding**: como la IP se resuelve una vez al
validar y otra al conectar, existe una ventana en la que el mismo nombre puede
apuntar primero a una IP pública y luego a una interna. El resultado es el mismo.

### El objetivo: 169.254.169.254 {#el-objetivo}

<figure>
<svg viewBox="0 0 900 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Diagrama de la cadena: el atacante llama al endpoint de prueba de webhooks; el servidor de MLflow sigue una redirección al endpoint de metadatos en 169.254.169.254 y devuelve al atacante las credenciales de la instancia">
  <defs>
    <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#6F7376"/>
    </marker>
  </defs>
  <g font-family="'Inter', sans-serif" font-size="12" fill="#0A0A0A">
    <rect x="20" y="112" width="150" height="56" rx="3" fill="none" stroke="#B9BEC2"/>
    <text x="95" y="136" text-anchor="middle">Atacante</text>
    <text x="95" y="153" text-anchor="middle" font-size="10" fill="#6F7376">sin credenciales</text>

    <rect x="330" y="112" width="170" height="56" rx="3" fill="none" stroke="#6B5D40" stroke-width="1.5"/>
    <text x="415" y="136" text-anchor="middle">Servidor MLflow</text>
    <text x="415" y="153" text-anchor="middle" font-size="10" fill="#6F7376">rol de instancia asignado</text>

    <rect x="690" y="112" width="190" height="56" rx="3" fill="none" stroke="#B9BEC2"/>
    <text x="785" y="132" text-anchor="middle">169.254.169.254</text>
    <text x="785" y="149" text-anchor="middle" font-size="10" fill="#6F7376">endpoint de metadatos</text>
  </g>
  <g font-family="'JetBrains Mono', monospace" font-size="10" fill="#5C6166">
    <line x1="170" y1="130" x2="326" y2="130" stroke="#6F7376" marker-end="url(#ar)"/>
    <text x="248" y="122" text-anchor="middle">1 · POST /webhooks/{id}/test</text>

    <line x1="500" y1="130" x2="686" y2="130" stroke="#6F7376" marker-end="url(#ar)"/>
    <text x="593" y="122" text-anchor="middle">2 · sigue el 302</text>

    <line x1="686" y1="150" x2="500" y2="150" stroke="#6F7376" marker-end="url(#ar)"/>
    <text x="593" y="166" text-anchor="middle">3 · credenciales STS</text>

    <line x1="326" y1="150" x2="170" y2="150" stroke="#6F7376" marker-end="url(#ar)"/>
    <text x="248" y="166" text-anchor="middle">4 · cuerpo reflejado</text>
  </g>
  <g font-family="'JetBrains Mono', monospace" font-size="10" fill="#6F7376">
    <text x="20" y="210">CVE-2026-64849 · CWE-918 · SSRF DE LECTURA COMPLETA · SIN AUTENTICAR</text>
  </g>
</svg>
<figcaption>La petición de prueba la emite el servidor de MLflow, que tiene el rol de instancia. El endpoint <code>/test</code> devuelve el cuerpo, así que las credenciales del paso 3 llegan al atacante en el paso 4.</figcaption>
</figure>

El SSRF, por sí solo, deja leer servicios internos: un panel sin exponer, una
base de datos con API HTTP, otro microservicio. Molesto, pero acotado. Lo que
convierte este fallo en un 9.3 es que en una instancia en la nube hay un destino
interno que casi siempre está y casi siempre da mucho: el **endpoint de
metadatos**.

## Por qué el endpoint de metadatos es el premio {#por-que-imds}

Toda instancia de AWS EC2 puede consultar `http://169.254.169.254/` para saber
cosas de sí misma. Si la instancia tiene un **rol de IAM asignado**, ese endpoint
entrega además **credenciales temporales** (`AccessKeyId`, `SecretAccessKey`,
`Token`) con los permisos del rol. GCP y Azure tienen su equivalente
(`metadata.google.internal`, el IMDS de Azure) con la misma idea.

Ese diseño es cómodo: la aplicación no guarda claves, las pide cuando las
necesita y rotan solas. El problema es que **cualquier cosa que pueda hacer una
petición HTTP desde la instancia puede pedirlas también** — y un SSRF es
exactamente eso.

AWS publicó **IMDSv2** en 2019 para cerrar esta vía. Cambia el protocolo de
acceso a los metadatos:

| | IMDSv1 | IMDSv2 |
|---|---|---|
| Obtener credenciales | un `GET` | primero un `PUT` para pedir un token, luego el `GET` con la cabecera `X-aws-ec2-metadata-token` |
| Salto de red | sin límite | `HttpPutResponseHopLimit` (1 por defecto en instancias nuevas) |
| Resistencia a SSRF | ninguna | alta |

La mayoría de los SSRF solo permiten `GET` y no dejan poner cabeceras
arbitrarias. Contra IMDSv2 eso no basta: sin el `PUT` previo y sin la cabecera del
token, la petición se rechaza. **IMDSv2 no arregla el SSRF de MLflow, pero hace
que no llegue a las credenciales.**

El matiz que lo mantiene vivo en 2026: IMDSv2 sigue siendo **opt-in**. Si
`HttpTokens` no está en `required`, IMDSv1 sigue respondiendo, y muchas
instancias antiguas lo tienen activo por compatibilidad.

## El 9.3 y el plazo {#el-numero-y-el-plazo}

### El vector, campo a campo {#el-vector}

El vector CVSS 3.1 publicado es:

```
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N
```

| Campo | Valor | Lectura |
|---|---|---|
| AV — vector de ataque | N (red) | alcanzable por red |
| AC — complejidad | L (baja) | no hace falta ganar una carrera ni condiciones raras |
| PR — privilegios | N (ninguno) | sin autenticar |
| UI — interacción | N (ninguna) | nadie tiene que hacer clic |
| S — alcance | C (cambiado) | salta de MLflow a otro sistema (el endpoint de metadatos) |
| **C — confidencialidad** | **H (alta)** | lee credenciales |
| **I — integridad** | **L (baja)** | apenas modifica nada |
| **A — disponibilidad** | **N (ninguna)** | no tira el servicio |

El 9.3 sale de las cuatro primeras casillas más el cambio de alcance. Pero mira
las tres últimas: **el impacto es de lectura**. Como ya vimos en [el análisis de
CVE-2026-56164]({{ '/research/cve-2026-56164-un-53-que-tambien-es-un-98/' | relative_url }}),
un número redondo resume mal un fallo. Aquí el 9.3 dice "crítico" y tiene razón;
lo que no dice es que "crítico" aquí significa *te roban las llaves*, no *te
ejecutan código*.

### Catorce días, no tres {#el-plazo}

CISA no puntúa con CVSS para fijar plazos. Desde **BOD 26-04** usa un árbol de
decisión con cuatro señales: exposición pública, presencia en el KEV,
automatización e impacto técnico. Del cruce salen escalones muy separados, desde
"la próxima ventana de mantenimiento" hasta **tres días** para el peor caso.

CVE-2026-64849 marca tres de las cuatro casillas sin discusión: es **alcanzable
desde Internet** (por eso lo escanean), está **en el KEV** y es **automatizable**
(una petición, sin sesión, metible en un escáner). La que falla es la cuarta. El
tramo de tres días exige **impacto técnico total** — control del sistema —, y
esto es divulgación de credenciales: impacto **parcial**. Por eso cae en el
escalón de 14 días.

Y el plazo real lo confirma. La entrada del catálogo:

| Campo | Valor |
|---|---|
| `dateAdded` | 2026-08-19 |
| `dueDate` | 2026-09-02 |
| Diferencia | **14 días** |

No es que CISA se lo tomara con calma. Es que el marco, aplicado a este fallo,
da 14. El plazo es coherente con lo que el fallo hace, ni duro ni blando —
exactamente el comportamiento que esperábamos de la directiva.

### Cómo sacarlo tú mismo {#reproducir}

El catálogo es un JSON público. La entrada de esta CVE se saca en una línea:

```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
| jq '.vulnerabilities[] | select(.cveID=="CVE-2026-64849")
      | {added: .dateAdded, due: .dueDate,
         producto: .product, accion: .requiredAction}'
```

Y el plazo en días, con el mismo patrón del artículo del KEV:

```python
import datetime
added = datetime.date(2026, 8, 19)
due   = datetime.date(2026, 9, 2)
print((due - added).days)   # 14
```

Todo lo que sigue sobre el árbol de decisión es interpretación mía sobre datos
públicos; el plazo, en cambio, es un dato que puedes recalcular ahora mismo.

## Qué se puede detectar {#deteccion}

Suponiendo que ya tengas una instancia de MLflow expuesta y quieras saber si la
han tocado, en orden de fiabilidad:

1. **Conexión saliente de la instancia a `169.254.169.254`.** Desde el proceso de
   una aplicación web esto no debería pasar casi nunca: quien habla con el
   endpoint de metadatos es el SDK de AWS, no el servidor web atendiendo una
   petición. Un acceso al endpoint **justo después** de un `POST` entrante a
   `/api/2.0/mlflow/webhooks/{id}/test` es la señal más limpia. Necesitas
   netflow o registro de conexiones del host.
2. **Creación de webhooks y llamadas a `/test` desde origen no autenticado o
   externo**, en el log de acceso del proxy inverso o en el propio log de MLflow.
3. **El pico de escaneo no dirigido tras el 17 de agosto.** Si guardas logs de
   esa semana, el patrón de peticiones a rutas de la API de webhooks desde muchas
   IPs distintas es visible a posteriori.

El aviso honesto, en la línea de [las reglas del artículo de
passkeys]({{ '/research/la-passkey-sincronizada-no-vive-en-el-tpm/' | relative_url }}):
MLflow por defecto **registra poco**. Sin un proxy inverso delante que guarde el
log de acceso, o sin instrumentar el host, es probable que solo te quede el
netflow del paso 1. Estas ideas están razonadas desde la mecánica del fallo, no
validadas contra telemetría real de un ataque.

## Qué se puede hacer {#mitigacion}

En orden de lo que más tapa a lo que menos:

1. **No exponer MLflow a Internet.** No trae autenticación por defecto. Detrás de
   una VPN o de un proxy con autenticación, y sin cara pública, este CVE deja de
   importar.
2. **`HttpTokens=required` en todas las instancias**, con `HttpEndpoint=enabled` y
   `HttpPutResponseHopLimit=1`. Esto neutraliza la **clase entera**: el próximo
   SSRF en la próxima herramienta tampoco llegará a las credenciales.
3. **Filtrado de egress** hacia `169.254.169.254` y el rango link-local desde
   cargas que no necesitan hablar con los metadatos.
4. **Actualizar a MLflow 3.15.0** (la corrección llegó en el PR #24258). Esto
   tapa *este* fallo. No tapa el siguiente.

El orden no es casual. Subir de versión es lo que primero pide todo el mundo y lo
que menos protege a medio plazo: es un parche de un síntoma. Los puntos 1 y 2 son
de arquitectura y valen para el CVE que aún no se ha publicado.

## Conclusiones {#conclusiones}

1. **CVE-2026-64849 es un fallo de confidencialidad.** El 9.3 es correcto, pero
   el impacto real es robo de credenciales temporales, no ejecución de código.
   El vector lo dice: `C:H / I:L / A:N`.
2. **El plazo de 14 días es coherente, no blando.** El tramo de tres días de
   BOD 26-04 exige impacto total; divulgación de credenciales es parcial. El
   marco, aplicado bien, da 14.
3. **La urgencia la marca "expuesto y automatizable".** Lo escanearon a las horas,
   antes de entrar en el KEV — el mismo patrón que se observa desde un honeypot.
   Eso no depende de la puntuación.
4. **El control que importa es viejo.** IMDSv2 lleva desde 2019 cerrando esta vía
   y sigue siendo opcional. Cada SSRF que llega a las credenciales lo hace sobre
   una instancia con IMDSv1 todavía activo.
5. **Actualizar es lo último de la lista útil, no lo primero.** Tapa este CVE;
   no tapa la clase.

## Limitaciones {#limitaciones}

- **Es un análisis de fuentes públicas**: el aviso de seguridad (GHSA-7gwp-5pfp-969j),
  la entrada del KEV y los informes de terceros. No he reproducido el ataque ni
  lo he lanzado contra ningún objetivo, y este artículo no contiene una cadena
  accionable para hacerlo.
- **La lectura del árbol de decisión de BOD 26-04 es interpretación mía.** CISA no
  publica qué combinación de señales aplicó a cada entrada del catálogo; deduzco
  el escalón de 14 días a partir del plazo real y de la definición de los tramos.
- **El plazo es una foto.** `dateAdded` y `dueDate` son del catálogo tal como
  estaba a principios de septiembre de 2026; las entradas del KEV se pueden
  revisar.
- **"MLflow no tiene auth por defecto" y "muchas instancias usan IMDSv1" son
  afirmaciones del estado habitual del producto y del parque de EC2**, no una
  medición propia sobre un conjunto concreto de sistemas.

## Referencias {#referencias}

<ol class="refs">
<li><a href="https://github.com/advisories/GHSA-7gwp-5pfp-969j">Unauthenticated full-read SSRF in webhook delivery (CVE-2026-64849)</a>. GitHub Advisory Database, con el vector CVSS, las versiones afectadas y el mecanismo del bypass.</li>
<li><a href="https://www.cisa.gov/news-events/alerts/2026/08/19/cisa-adds-one-known-exploited-vulnerability-catalog">CISA Adds One Known Exploited Vulnerability to Catalog</a>. CISA, 19 de agosto de 2026.</li>
<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>. CISA. Entrada de CVE-2026-64849: <code>dateAdded</code> 2026-08-19, <code>dueDate</code> 2026-09-02.</li>
<li><a href="https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk">BOD 26-04 — Prioritizing Security Updates Based on Risk</a> y su <a href="https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk">guía de implementación</a>. CISA, con la tabla de escalones de plazo.</li>
<li><a href="https://github.com/mlflow/mlflow/pull/24258">Fix DNS-rebinding SSRF bypass in webhook delivery</a>. mlflow/mlflow PR #24258, incluido en la versión 3.15.0.</li>
<li><a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html">Use IMDSv2</a>. AWS EC2 User Guide, sobre <code>HttpTokens</code>, la cabecera de token y el <code>HttpPutResponseHopLimit</code>.</li>
<li><a href="https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html">Attackers Exploit MLflow SSRF Flaw to Steal Cloud Credentials and Secrets</a>. The Hacker News, con la cronología de escaneo de watchTowr y VulnCheck.</li>
<li><a href="https://www.securityweek.com/mlflow-vulnerability-exploited-for-cloud-credential-theft/">MLflow Vulnerability Exploited for Cloud Credential Theft</a>. SecurityWeek.</li>
</ol>
