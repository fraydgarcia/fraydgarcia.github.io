# tools/

## encrypt-writeup.js — writeups protegidos con passphrase

Publica un writeup cuyo contenido viaja cifrado (AES-256-GCM, clave derivada con
PBKDF2-SHA256) y se descifra en el navegador con una passphrase. El texto en claro
**no se commitea**. Cifrado (Node Web Crypto) y descifrado (navegador) usan los
mismos primitivos, sin dependencias externas.

### Flujo

1. Escribe el writeup en markdown, como cualquier otro.
2. Renderízalo a HTML (el navegador lo inyecta como `innerHTML`):

   ```bash
   kramdown --input GFM entrada.md > entrada.html
   # o copia el <div class="article-body"> de un `jekyll build` local
   ```

3. Cífralo:

   ```bash
   node tools/encrypt-writeup.js entrada.html cohort
   # pide la passphrase por stdin; también admite pasarla como 3.º argumento
   ```

4. Edita las cabeceras marcadas en `_writeups/<fecha>-cohort.md` (título, lead,
   stack, description). El layout `writeup-locked` muestra esas cabeceras en claro
   y pide la passphrase para el resto.
5. Opcional: añade la tarjeta al índice `/writeups/` marcándola como protegida.

### Aviso honesto

En un sitio estático el cifrado es **solo del lado del cliente**: quien descargue
la página puede intentar romper la passphrase offline. Sirve como barrera de
disuasión y para no indexar el contenido —usa una passphrase larga—, no como
control de acceso fuerte.

**No publiques por esta vía soluciones de máquinas de HTB activas.** Aunque vayan
cifradas, si alguien las descifra infringen las reglas de la plataforma. Reserva el
mecanismo para contenido que ya sea legal publicar pero que prefieras no dejar
indexado.
