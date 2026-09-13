#!/usr/bin/env node
/*
 * encrypt-writeup.js — cifra un writeup para publicarlo protegido con passphrase.
 *
 * Genera una página de la colección `_writeups` con `layout: writeup-locked`:
 * el contenido viaja cifrado (AES-256-GCM, clave derivada con PBKDF2-SHA256) y
 * se descifra EN EL NAVEGADOR con la passphrase. El texto en claro NUNCA se
 * commitea. Usa la Web Crypto API de Node, idéntica a la del navegador, así que
 * cifrado y descifrado comparten primitivos.
 *
 * Uso:
 *   node tools/encrypt-writeup.js <entrada.html> <slug> [passphrase]
 *
 * - <entrada.html>: el cuerpo del writeup YA renderizado a HTML (no markdown),
 *   porque el navegador lo inyecta como innerHTML. Para obtenerlo: renderiza tu
 *   markdown con `jekyll build` en una rama local y copia el <div class="article-body">,
 *   o pásalo por `kramdown entrada.md > entrada.html`.
 * - <slug>: nombre del fichero de salida, p.ej. "cohort".
 * - Si no pasas passphrase, se pide por stdin (no queda en el historial de shell).
 *
 * Salida: _writeups/<fecha>-<slug>.md  (con las metacabeceras que edites a mano)
 *
 * AVISO honesto: en un sitio estático el cifrado es SOLO del lado del cliente.
 * Quien descargue la página puede intentar romper la passphrase offline. Úsalo
 * como barrera de disuasión y para no indexar el contenido, con una passphrase
 * larga. NO publiques por esta vía soluciones de máquinas de HTB activas: aunque
 * cifradas, si se descifran infringen las reglas de la plataforma.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { webcrypto } = crypto;

const ITERATIONS = 250000;

async function main() {
  const [inputPath, slug, passArg] = process.argv.slice(2);
  if (!inputPath || !slug) {
    console.error('Uso: node tools/encrypt-writeup.js <entrada.html> <slug> [passphrase]');
    process.exit(1);
  }
  const plaintext = fs.readFileSync(inputPath, 'utf8');
  const passphrase = passArg || await promptHidden('Passphrase: ');
  if (!passphrase) { console.error('Passphrase vacía.'); process.exit(1); }

  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();

  const baseKey = await webcrypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const cipherBuf = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(plaintext));

  const b64 = (u8) => Buffer.from(u8).toString('base64');
  const date = new Date().toISOString().slice(0, 10);
  const outFile = path.join('_writeups', `${date}-${slug}.md`);

  const frontMatter = [
    '---',
    'layout: writeup-locked',
    'title: "TÍTULO DEL WRITEUP"      # edítalo',
    'plataforma: Hack The Box',
    'so: Linux',
    'dificultad: Medium',
    'lead: "Resumen público visible sin passphrase."   # edítalo',
    'stack: "CVE · técnica · técnica"                    # edítalo',
    'description: "Meta description pública."            # edítalo',
    `iterations: ${ITERATIONS}`,
    `salt: "${b64(salt)}"`,
    `iv: "${b64(iv)}"`,
    `cipher: "${b64(new Uint8Array(cipherBuf))}"`,
    '---',
    '',
  ].join('\n');

  fs.writeFileSync(outFile, frontMatter);
  console.log(`[+] Escrito ${outFile}`);
  console.log('[!] Edita las cabeceras marcadas y añade la tarjeta al índice si procede.');
  console.log('[!] El texto en claro NO se ha commiteado. No pierdas la passphrase.');
}

// Lee una línea de stdin sin eco, comparando por código de carácter para no
// incrustar bytes de control en el fuente.
function promptHidden(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    let buf = '';
    stdin.on('data', function onData(chunk) {
      const s = chunk.toString('utf8');
      for (const ch of s) {
        const code = ch.charCodeAt(0);
        if (code === 10 || code === 13 || code === 4) { // \n, \r, EOF
          if (stdin.setRawMode) stdin.setRawMode(wasRaw);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          return resolve(buf);
        } else if (code === 3) { // Ctrl-C
          process.stdout.write('\n');
          process.exit(1);
        } else if (code === 127 || code === 8) { // backspace
          buf = buf.slice(0, -1);
        } else {
          buf += ch;
        }
      }
    });
  });
}

main().catch((e) => { console.error(e); process.exit(1); });
