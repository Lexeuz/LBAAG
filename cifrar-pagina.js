/* Herramienta de cifrado para la capa de acceso.
   Uso: node cifrar.js <archivo-de-entrada.html> <contraseña>
   Imprime un objeto JS { salt, iv, iter, data } en base64, listo para
   pegar dentro del <script> de la pantalla de acceso (PAYLOAD = {...}).
   PBKDF2-HMAC-SHA256 + AES-256-GCM, compatible con Web Crypto (SubtleCrypto)
   del navegador: el auth tag de GCM se concatena al final del ciphertext,
   tal como lo produce/espera crypto.subtle.
*/
const fs = require('fs');
const crypto = require('crypto');

const [, , inFile, password] = process.argv;
if (!inFile || !password) {
  console.error('Uso: node cifrar.js <archivo.html> <contraseña>');
  process.exit(1);
}

const plaintext = fs.readFileSync(inFile); // Buffer, preserva bytes exactos (UTF-8)

const ITER = 300000;
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);

const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, ITER, 32, 'sha256');

const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const authTag = cipher.getAuthTag();
const combined = Buffer.concat([ciphertext, authTag]); // formato esperado por SubtleCrypto AES-GCM

const out = {
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  iter: ITER,
  data: combined.toString('base64')
};

console.log(JSON.stringify(out));
console.error('OK: plaintext bytes =', plaintext.length, '| ciphertext(+tag) bytes =', combined.length);
