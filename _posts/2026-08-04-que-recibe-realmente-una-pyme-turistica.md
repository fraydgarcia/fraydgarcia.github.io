---
layout: research
title: "Qué recibe realmente una PYME turística expuesta a Internet"
date: 2026-08-04
lead: "Un honeypot multi-servicio simulando un alojamiento de Lanzarote, expuesto sin publicidad ni indexación. Casi 200 intentos de intrusión en menos de una hora."
description: "Resultados de siete semanas de captura con un honeypot T-Pot que simula la infraestructura de una PYME hotelera: volumen, origen y naturaleza de los ataques recibidos."
stack: "T-Pot · Cowrie · H0neytr4p · Tanner · Suricata · Elastic"
---

## Introducción

Cuando se habla de ciberseguridad con una PYME hotelera, la conversación suele encallar en la misma frase: *"¿quién iba a querer atacarnos a nosotros?"*. Es una pregunta razonable. Un apartamento turístico de veinte plazas no guarda propiedad intelectual, no cotiza en bolsa y no aparece en las noticias.

La respuesta habitual —"todo el mundo es un objetivo"— es cierta pero inútil, porque no se puede medir. Así que en lugar de repetirla, monté algo que pudiera responderla con datos: un **honeypot** que simulara la infraestructura típica de un alojamiento turístico de Lanzarote, lo expuse a Internet y conté lo que llegaba.

Este artículo recoge lo que registró. La conclusión adelantada es que la pregunta está mal formulada: **nadie quiere atacarles a ellos en particular**, y eso es precisamente lo que hace que los ataquen.

## El montaje

La plataforma es [T-Pot](https://github.com/telekom-security/tpotce), una distribución que orquesta varios honeypots en contenedores Docker con una pila Elastic detrás para centralizar y visualizar los eventos.

Desplegado sobre una instancia de **Oracle Cloud Free Tier**, con un dominio señuelo registrado a nombre de un alojamiento ficticio para que la superficie fuese coherente: si un atacante resolvía el nombre, encontraba algo que parecía un hotel pequeño.

Los sensores activos y qué simulaba cada uno:

| Honeypot | Superficie que simula |
|---|---|
| `Cowrie` | SSH y Telnet, con sesión interactiva completa |
| `H0neytr4p` | Multi-protocolo, varios puertos |
| `Tanner` | Aplicación web, vulnerabilidades HTTP/HTTPS |
| `Ciscoasa` | Interfaz HTTPS de un firewall Cisco |
| `Dionaea` | Captura de malware |

Cowrie es el más informativo de todos: no solo registra el intento de autenticación, sino que **deja entrar** al atacante a un sistema de archivos falso y graba la sesión entera — qué comandos ejecuta, qué descarga, qué intenta hacer después.

> El sistema se expuso sin ninguna campaña de publicidad, sin enviar la URL a nadie y sin indexación web. Nadie sabía que existía.

## Resultados

### El tiempo hasta el primer ataque

En **menos de 60 minutos** desde la exposición, el sistema registró **casi 200 intentos de intrusión automatizados**.

Ese dato, por sí solo, responde a la pregunta del principio mejor que cualquier argumento. No hubo un periodo de gracia, ni una fase en la que alguien "descubriera" el servidor. La superficie de ataque de Internet se recorre de forma continua y exhaustiva, y un servidor nuevo entra en las listas en cuestión de minutos.

En las **primeras 24 horas**: **417 ataques** registrados.

### Volumen por sensor

Distribución de eventos durante el periodo de captura (datos parciales):

| Honeypot | Eventos | Servicio |
|---|---|---|
| `H0neytr4p` | ~16.000 | Multi-protocolo |
| `Cowrie` | ~11.000 | SSH / Telnet |
| `Tanner` | ~5.000 | HTTP / HTTPS |
| `Ciscoasa` | ~1.000 | HTTPS (firewall) |
| **Total** | **~33.000** | |

SSH y Telnet concentran un tercio del total. Es el patrón esperable: son los servicios con más superficie de fuerza bruta automatizada y los que más aparecen expuestos por error en instalaciones pequeñas.

### Origen

Los cinco países con mayor volumen:

1. Estados Unidos
2. Holanda
3. Filipinas
4. Argentina
5. Arabia Saudí

Conviene leer esta lista con cuidado. **No indica quién ataca, indica desde dónde sale el tráfico.** Estados Unidos y Holanda encabezan la lista porque concentran infraestructura de alojamiento barata y abundante, no porque el ataque se origine allí. El proyecto excluyó explícitamente la atribución de su alcance: los datos permiten análisis estadístico y de patrones, no perfiles individuales.

## Lectura de los datos

### El ataque es indiscriminado, y por eso llega

El hallazgo relevante no es el volumen, es su **naturaleza**. Ninguno de esos 33.000 eventos iba dirigido a un hotel de Lanzarote. Iban dirigidos a *cualquier cosa que respondiera*.

Eso cambia el modelo de amenaza de una PYME por completo. La pregunta deja de ser *"¿tenemos algo que alguien quiera?"* y pasa a ser *"¿estamos por debajo del umbral de lo que un escáner automático explota sin intervención humana?"*. Es una pregunta mucho más fácil de responder, y mucho más fácil de accionar.

### El tiempo de exposición es la métrica que importa

Si el primer intento llega en menos de una hora, el margen para "ya lo configuraremos bien la semana que viene" no existe. Un servicio se despliega endurecido o se despliega comprometido; no hay un estado intermedio que dure.

Esto tiene una consecuencia práctica concreta para un alojamiento: **el momento de mayor riesgo no es cuando el sistema lleva años funcionando, sino el día que se instala algo nuevo.** Un TPV nuevo, una cámara IP, un router que el proveedor deja con las credenciales por defecto "temporalmente".

### Lo que un escáner busca es lo barato

El reparto por sensor lo dice: SSH, Telnet y web. No exploits sofisticados — credenciales por defecto, servicios expuestos que no deberían estarlo y vulnerabilidades web conocidas con exploit público.

Eso es una buena noticia, porque significa que las medidas que cortan la mayor parte del tráfico malicioso son también las más baratas.

## Conclusiones

Para un alojamiento pequeño, de los datos se deducen cuatro cosas:

1. **La exposición se paga en minutos, no en meses.** No existe el periodo de gracia.
2. **No hace falta ser un objetivo para ser atacado.** El ataque no selecciona; recorre.
3. **La mayor parte del tráfico malicioso es automatizado y busca lo fácil.** Autenticación por clave en vez de contraseña, cerrar los servicios de administración al exterior y cambiar las credenciales por defecto neutralizan la mayoría.
4. **Cada servicio nuevo reinicia el reloj.** El riesgo se concentra en el despliegue, no en la operación.

## Limitaciones

La honestidad sobre lo que estos datos **no** son es parte del resultado:

- El periodo de captura fue de **7 semanas**, por debajo de las 8–12 planificadas. El conjunto de datos es menor de lo previsto y varios objetivos cuantitativos quedaron en curso al cerrar la memoria.
- Las cifras por sensor son **parciales**, tomadas del panel durante el periodo, no un recuento final consolidado.
- Restricciones de memoria en la instancia inicial obligaron a **deshabilitar temporalmente Conpot y Elasticpot**, así que las superficies ICS/SCADA y Elasticsearch están infrarrepresentadas.
- No se hizo atribución. Los orígenes geográficos son de la IP de salida, no del actor.

Un honeypot mide lo que llega a un señuelo, no lo que le pasaría exactamente a una instalación real con su propio tráfico legítimo y sus propios usuarios. Es un indicador de la presión de fondo de Internet, y como tal hay que leerlo.

## Referencias

<ol class="refs">
<li><a href="https://github.com/telekom-security/tpotce">T-Pot — The All In One Honeypot Platform</a>. Deutsche Telekom Security.</li>
<li><a href="https://github.com/cowrie/cowrie">Cowrie SSH/Telnet Honeypot</a>.</li>
<li><a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a>, marco de referencia usado para clasificar las técnicas observadas.</li>
<li><a href="https://github.com/fraydgarcia/tfg-honeypot-turismo">Memoria completa del proyecto</a> — 37 páginas, con la metodología, el despliegue y los datos originales.</li>
</ol>
