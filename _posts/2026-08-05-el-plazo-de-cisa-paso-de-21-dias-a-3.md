---
layout: research
title: "El plazo de CISA pasó de 21 días a 3"
date: 2026-08-05
author: "Fray García"
image: "/assets/img/og/kev-plazos.png"
lead: "Durante tres años, casi todo lo que entraba en el catálogo KEV venía con 21 días para parchear. En 2026 ese número se ha desplomado a 3. El catálogo entero — 1.660 entradas — lo enseña mes a mes."
description: "Análisis del catálogo Known Exploited Vulnerabilities de CISA completo: cómo el plazo de remediación pasó de un estándar estable de 21 días a una mediana de 3 en 2026, qué cambió con BOD 26-04 y qué implica para un equipo pequeño."
stack: "CISA KEV · BOD 26-04 · SSVC · Python · curl"
toc:
  - title: "Introducción"
    id: introduccion
  - title: "El dato"
    id: el-dato
    children:
      - title: "Cómo sacarlo tú mismo"
        id: reproducir
  - title: "La serie: tres años clavados en 21"
    id: serie
  - title: "Qué cambió: BOD 26-04"
    id: bod
  - title: "Por qué tres días y no veintiuno"
    id: por-que
  - title: "Qué significa si no eres una agencia federal"
    id: que-significa
  - title: "Qué se puede hacer con un equipo pequeño"
    id: que-hacer
  - title: "Conclusiones"
    id: conclusiones
  - title: "Limitaciones"
    id: limitaciones
  - title: "Referencias"
    id: referencias
---

## Introducción {#introduccion}

Escribiendo [el análisis de CVE-2026-56164]({{ '/research/cve-2026-56164-un-53-que-tambien-es-un-98/' | relative_url }}) me llamó la atención un detalle que dejé apuntado sin desarrollar: CISA metió esa vulnerabilidad en su catálogo de fallos explotados el 14 de julio y puso como fecha límite el 17. **Tres días.**

Me sonaba raro, porque el número que tenía en la cabeza para el catálogo KEV era 21 días. Así que en lugar de fiarme de mi memoria, me descargué el catálogo entero y lo conté.

El resultado es que mi memoria estaba bien y el catálogo ha cambiado. **El plazo de 21 días fue el estándar de facto durante tres años y en 2026 se ha roto.** Desde junio, la mediana es de tres días.

Este artículo es ese recuento: qué dice el catálogo completo, qué cambió para que cambiara el plazo y qué consecuencias tiene para quien administra sistemas sin un equipo detrás.

## El dato {#el-dato}

El catálogo **Known Exploited Vulnerabilities** de CISA es la lista pública de vulnerabilidades con explotación confirmada en el mundo real. Cada entrada trae, entre otros campos, `dateAdded` y `dueDate`: cuándo entró y para cuándo hay que haberla remediado. La diferencia entre ambas es el plazo.

Sobre la versión **2026.08.04** del catálogo — **1.660 entradas**, desde el 3 de noviembre de 2021 —, la mediana del plazo por año:

| Año | Entradas | Mediana | Plazo más frecuente |
|---|---|---|---|
| 2021 | 311 | 181 días | 181 días (61 %) |
| 2022 | 555 | 21 días | 21 días (73 %) |
| 2023 | 187 | 21 días | 21 días (**95 %**) |
| 2024 | 186 | 21 días | 21 días (**94 %**) |
| 2025 | 245 | 21 días | 21 días (**92 %**) |
| 2026 | 176 | 14 días | **3 días** (39 %) |

Los 181 días de 2021 son el arranque del catálogo: a las vulnerabilidades antiguas que entraron el primer día se les dio medio año. A partir de 2022 el sistema se estabiliza en 21 días y ahí se queda. Entre 2023 y 2025, **más de nueve de cada diez entradas traen exactamente 21 días**.

Y en 2026 se rompe. Mes a mes:

<figure>
<svg viewBox="0 0 900 380" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Gráfico: la mediana del plazo de remediación del catálogo KEV se mantiene en 21 días de 2022 a febrero de 2026, baja a 14 en marzo y a 3 en junio">
  <g font-family="'JetBrains Mono', monospace" font-size="11" fill="#6F7376">
    <text x="72" y="75" text-anchor="end">21</text>
    <text x="72" y="148" text-anchor="end">14</text>
    <text x="72" y="221" text-anchor="end">7</text>
    <text x="72" y="294" text-anchor="end">0</text>
  </g>
  <g stroke="#EBEEF1" stroke-width="1">
    <line x1="84" y1="71" x2="870" y2="71"/>
    <line x1="84" y1="144" x2="870" y2="144"/>
    <line x1="84" y1="217" x2="870" y2="217"/>
  </g>
  <line x1="84" y1="290" x2="870" y2="290" stroke="#B9BEC2" stroke-width="1"/>

  <path d="M120,71 H480 V144 H676 V259 H840" fill="none" stroke="#6B5D40" stroke-width="2.5"/>
  <g fill="#0A0A0A">
    <circle cx="120" cy="71" r="3.5"/><circle cx="186" cy="71" r="3.5"/>
    <circle cx="251" cy="71" r="3.5"/><circle cx="316" cy="71" r="3.5"/>
    <circle cx="382" cy="71" r="3.5"/><circle cx="447" cy="71" r="3.5"/>
    <circle cx="513" cy="144" r="3.5"/><circle cx="578" cy="144" r="3.5"/>
    <circle cx="644" cy="144" r="3.5"/>
    <circle cx="709" cy="259" r="3.5"/><circle cx="775" cy="259" r="3.5"/>
    <circle cx="840" cy="259" r="3.5"/>
  </g>

  <g font-family="'JetBrains Mono', monospace" font-size="10" fill="#6F7376" text-anchor="middle">
    <text x="120" y="311">2022</text><text x="186" y="311">2023</text>
    <text x="251" y="311">2024</text><text x="316" y="311">2025</text>
    <text x="382" y="311">ENE</text><text x="447" y="311">FEB</text>
    <text x="513" y="311">MAR</text><text x="578" y="311">ABR</text>
    <text x="644" y="311">MAY</text><text x="709" y="311">JUN</text>
    <text x="775" y="311">JUL</text><text x="840" y="311">AGO</text>
  </g>
  <g font-family="'JetBrains Mono', monospace" font-size="10" fill="#6F7376" text-anchor="middle">
    <text x="251" y="330">MEDIANA ANUAL</text>
    <text x="611" y="330">2026, MES A MES</text>
  </g>
  <line x1="349" y1="40" x2="349" y2="296" stroke="#DADCDE" stroke-width="1" stroke-dasharray="3 4"/>

  <g font-family="'Inter', sans-serif" font-size="12">
    <text x="130" y="58" fill="#5C6166">21 días — el estándar durante cuatro años</text>
    <text x="709" y="284" fill="#0A0A0A" font-weight="600">3 días</text>
    <text x="513" y="132" fill="#5C6166">14</text>
  </g>
  <g font-family="'JetBrains Mono', monospace" font-size="10" fill="#6F7376">
    <text x="84" y="360">MEDIANA DEL PLAZO DE REMEDIACIÓN · CATÁLOGO KEV 2026.08.04 · N=1.660</text>
  </g>
</svg>
<figcaption>Mediana del plazo entre <code>dateAdded</code> y <code>dueDate</code>. Los cuatro primeros puntos son medianas anuales; los ocho siguientes, mensuales de 2026. Calculado sobre el catálogo completo.</figcaption>
</figure>

| Mes de 2026 | Entradas | Mediana | Plazo mínimo |
|---|---|---|---|
| Enero | 17 | 21 días | 3 |
| Febrero | 28 | 21 días | 2 |
| Marzo | 26 | 14 días | 3 |
| Abril | 31 | 14 días | 3 |
| Mayo | 21 | 14 días | 3 |
| Junio | 23 | **3 días** | 3 |
| Julio | 26 | **3 días** | 3 |
| Agosto (parcial) | 4 | **3 días** | 3 |

De las 176 entradas de 2026, **71 traen tres días o menos**. La primera con plazo de tres días es del 27 de enero: `CVE-2026-24858`, de Fortinet.

### Cómo sacarlo tú mismo {#reproducir}

Nada de esto necesita acceso privilegiado ni herramientas de pago. El catálogo es un JSON público:

```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o kev.json
```

Y el cálculo cabe en unas pocas líneas:

```python
import json, datetime, statistics, collections

kev = json.load(open("kev.json"))["vulnerabilities"]
plazo = lambda v: (datetime.date.fromisoformat(v["dueDate"])
                   - datetime.date.fromisoformat(v["dateAdded"])).days

por_mes = collections.defaultdict(list)
for v in kev:
    por_mes[v["dateAdded"][:7]].append(plazo(v))

for mes in sorted(por_mes):
    print(mes, len(por_mes[mes]), statistics.median(por_mes[mes]))
```

Lo digo porque importa más de lo que parece: **este artículo no contiene ni un dato que no puedas recalcular en dos minutos.** Si algo de lo que sigue te parece dudoso, compruébalo.

## La serie: tres años clavados en 21 {#serie}

Merece la pena detenerse en lo estable que era esto antes de 2026. En 2023, de 187 entradas, **177 traían exactamente 21 días**. En 2024, 175 de 186. En 2025, 226 de 245.

Eso no es una tendencia: es una regla. El plazo no dependía de la vulnerabilidad. Daba igual que fuera una ejecución remota sin autenticar en un dispositivo de perímetro o una escalada local que requiere ya estar dentro: 21 días para las dos.

Y tenía su lógica. Un plazo fijo es fácil de auditar, fácil de planificar y no obliga a nadie a discutir cada caso. El coste es que trata igual lo que no es igual.

## Qué cambió: BOD 26-04 {#bod}

En 2026 CISA publicó la directiva **BOD 26-04, *Prioritizing Security Updates Based on Risk***, que **deroga y sustituye a BOD 22-01** — la que creó el catálogo KEV y el plazo fijo — y también a BOD 19-02. Obliga a las agencias del Ejecutivo Civil Federal de EE. UU. y a los proveedores cloud de FedRAMP.

El cambio de fondo es que el plazo deja de ser una constante y pasa a salir de una combinación de señales de riesgo:

| Señal | Qué pregunta |
|---|---|
| Exposición pública | ¿Es alcanzable desde Internet? |
| Presencia en el KEV | ¿Hay explotación confirmada? |
| Automatizable | ¿Se puede lanzar a escala sin intervención humana? |
| Impacto técnico | ¿Control parcial o control total del sistema? |

Del cruce salen escalones muy separados: desde **arreglarlo en la próxima actualización del sistema**, para lo que no está expuesto ni explotado, hasta **tres días** para el peor caso. Y ese peor caso —expuesto, en el KEV, automatizable y con control total— no se cierra parcheando: la directiva exige además **triaje forense**, es decir, comprobar si el sistema ya estaba comprometido *antes* de aplicar el parche.

Es el mismo marco de decisión que ya vimos actuar en el caso de SharePoint: no una nota de 0 a 10, sino un árbol de preguntas. Lo que allí se veía en un CVE suelto, aquí se ve en la serie completa.

## Por qué tres días y no veintiuno {#por-que}

La lectura fácil sería "CISA se ha puesto dura". Creo que es al revés, y los datos lo apoyan: la directiva **relaja** los plazos de casi todo y los aprieta solo donde hace falta.

Fíjate en la columna del mínimo de la tabla mensual: ya en enero y febrero de 2026, con mediana de 21, había entradas con plazos de 2 y 3 días. El escalón no apareció de golpe en junio; lo que pasó en junio es que **el perfil de lo que entra en el catálogo se llenó de casos del tramo peor**.

Y ahí está lo interesante, porque la razón por la que el plazo se acorta es la misma que medí en el honeypot: **la explotación automatizada no espera**. Si un fallo es alcanzable desde Internet, no requiere credenciales y se puede meter en un escáner, el tiempo entre que se publica y que alguien lo prueba contra todo el rango de direcciones no se mide en semanas. Un plazo de 21 días para algo así no protege de nada; solo documenta con retraso.

Un matiz que conviene no pasar por alto: el porcentaje de entradas con uso conocido en campañas de ransomware **no ha subido** — 23 % en 2024, 11 % en 2025, 12 % en lo que va de 2026. El endurecimiento no responde a más ransomware, sino a una forma distinta de clasificar la urgencia.

## Qué significa si no eres una agencia federal {#que-significa}

Formalmente, nada: BOD 26-04 obliga a agencias federales estadounidenses, no a una PYME de Lanzarote ni a una empresa española.

En la práctica, bastante, por dos motivos.

El primero es que **el catálogo KEV se ha convertido en el estándar informal de "esto sí importa"** para medio sector. Aseguradoras, marcos de cumplimiento, herramientas de gestión de vulnerabilidades y pliegos de contratación lo referencian. Cuando el emisor de esa lista decide que ciertos casos requieren tres días, ese número acaba filtrándose a los contratos de mantenimiento de todo el mundo.

El segundo es más directo: **el plazo no lo pone CISA, lo pone el atacante.** CISA solo lo está midiendo mejor. Tu servidor no tiene 21 días porque una directiva lo dijera; tiene el tiempo que tarde alguien en incluirlo en un barrido.

La consecuencia operativa incomoda: si el escenario peor exige tres días, **la ventana de mantenimiento tiene que existir antes que el CVE**. No se puede negociar con dirección un corte de servicio de urgencia en 72 horas si no hay un procedimiento previo que lo permita. La preparación es el control, no la reacción.

## Qué se puede hacer con un equipo pequeño {#que-hacer}

Sin plantilla dedicada, el margen es estrecho pero no nulo:

1. **Saber qué tienes expuesto.** El primer filtro del árbol de decisión es la exposición pública, y es también el único que puedes cambiar tú de forma barata. Un inventario de lo que responde desde Internet vale más que cualquier suscripción de inteligencia.
2. **Suscribirse al KEV, no a "todos los CVE".** Son unas 180 entradas al año, no 40.000. Es una cantidad que una persona puede revisar.
3. **Tener la ventana de mantenimiento acordada de antemano**, con el procedimiento de aviso y de reversión escrito. Tres días no dan para inventarse un proceso.
4. **Separar parchear de comprobar.** La parte de BOD 26-04 que más se ignora es el triaje forense: si algo llevaba días expuesto y explotable, parchear y seguir no responde a la pregunta de si ya entraron. Los artefactos de compromiso sobreviven al parche — [con SharePoint eso se ve muy claro]({{ '/research/cve-2026-56164-un-53-que-tambien-es-un-98/#cadena' | relative_url }}).
5. **Aceptar que no todo es urgente.** Esta es la otra cara, y la más útil: la directiva permite aplazar explícitamente lo de bajo riesgo. Un equipo pequeño que intenta parchearlo todo con la misma prisa llega tarde a lo que importa.

## Conclusiones {#conclusiones}

1. **El estándar de 21 días existió y ha terminado.** Tres años con más del 90 % de las entradas en ese plazo exacto, y una mediana de 3 días desde junio de 2026.
2. **El cambio no es de intensidad, es de método.** Se pasa de un plazo fijo para todo a un plazo derivado de exposición, explotación confirmada, automatización e impacto.
3. **La urgencia ya no la fija la gravedad.** La fija que el fallo sea alcanzable y automatizable — exactamente lo que se observa desde un honeypot.
4. **Tres días no es un objetivo de parcheo, es un objetivo de preparación.** Se cumple con la ventana de mantenimiento y el procedimiento ya montados, o no se cumple.
5. **Parchear no responde si ya entraron.** El tramo más urgente exige triaje forense, y esa parte no tiene atajo.

## Limitaciones {#limitaciones}

- **El KEV solo contiene lo explotado *y conocido*.** No es el universo de lo que se explota; es el subconjunto que CISA ha confirmado y decidido publicar. Los cambios en el catálogo pueden reflejar cambios en el criterio de publicación tanto como cambios en la realidad.
- **Mido plazos, no cumplimiento.** El catálogo dice para cuándo había que arreglarlo, no si alguien lo arregló. No tengo ningún dato sobre tasas de cumplimiento reales.
- **Correlación, no causa demostrada.** Atribuyo el escalón a BOD 26-04 porque coincide en el tiempo y porque la directiva describe exactamente esos escalones, pero no he verificado entrada por entrada qué combinación del árbol le aplicaron a cada una.
- **Agosto de 2026 son cuatro entradas.** La mediana de un mes con `n=4` no sostiene ninguna tendencia por sí sola; está en la tabla por completitud.
- **La obligación es solo para agencias FCEB de EE. UU.** Todo lo que digo sobre su efecto fuera de ese ámbito es interpretación mía, no un requisito.
- **Es una foto del 4 de agosto de 2026.** El catálogo cambia cada semana; el cálculo es reproducible, el resultado puede no serlo dentro de unos meses.

## Referencias {#referencias}

<ol class="refs">
<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>. CISA. Versión 2026.08.04, 1.660 entradas, descargada el 5 de agosto de 2026.</li>
<li><a href="https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk">BOD 26-04 — Prioritizing Security Updates Based on Risk</a>. CISA.</li>
<li><a href="https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk">BOD 26-04 — Implementation Guidance</a>. CISA, con la tabla de escalones y el requisito de triaje forense.</li>
<li><a href="https://www.cisa.gov/news-events/directives/binding-operational-directive-22-01">BOD 22-01</a>. CISA, la directiva derogada que creó el catálogo y el plazo fijo.</li>
<li><a href="https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc">SSVC — Stakeholder-Specific Vulnerability Categorization</a>. CISA, el árbol de decisión detrás de los escalones.</li>
<li><a href="https://nucleussec.com/blog/navigating-requirements-cisa-bod-26-04/">Navigating the requirements of CISA BOD 26-04</a>. Nucleus Security, desglose de los tramos de plazo.</li>
</ol>
