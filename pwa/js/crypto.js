/**
 * crypto.js - qmrClau WebCrypto implementation
 * 100% compatible with the Python qmrClau .vkdb format
 *
 * File format:
 *   [0:4]   b"VKDB"  magic
 *   [4:6]   0x0003   version (big-endian uint16)
 *   [6:38]  salt     32 bytes random
 *   [38:54] iv       16 bytes random
 *   [54:86] HMAC-SHA256(key, salt+iv+ciphertext)  32 bytes
 *   [86:]   AES-256-CBC(PKCS7(JSON.encode(data)), key, iv)
 *
 * Key derivation: PBKDF2-HMAC-SHA256, 200000 iterations, 32-byte key
 * Same key used for both AES-CBC and HMAC.
 */

const DB_VERSION = 3;
const ITERATIONS = 200_000;
const MAGIC = new Uint8Array([0x56, 0x4B, 0x44, 0x42]); // "VKDB"

function concat(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Derive a raw 256-bit key from password + salt using PBKDF2-HMAC-SHA256.
 * Returns ArrayBuffer (32 bytes).
 */
async function _deriveRawKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  return crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
}

/**
 * Import raw key bytes for AES-CBC usage.
 */
async function _importAesKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-CBC' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Import raw key bytes for HMAC-SHA256 usage.
 */
async function _importHmacKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * Encrypt data object and return a Uint8Array in .vkdb format.
 * @param {Object} data  - The JS object to encrypt (will be JSON-serialized)
 * @param {string} password - Master password (UTF-8)
 * @returns {Uint8Array}
 */
export async function encryptDB(data, password) {
  // Generate random salt (32 bytes) and IV (16 bytes)
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv   = crypto.getRandomValues(new Uint8Array(16));

  // Derive key
  const rawKey = await _deriveRawKey(password, salt);

  // Encrypt with AES-256-CBC (WebCrypto applies PKCS7 padding automatically)
  const aesKey = await _importAesKey(rawKey);
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: iv },
    aesKey,
    plaintext
  );
  const ciphertext = new Uint8Array(ciphertextBuf);

  // Compute HMAC-SHA256(key, salt || iv || ciphertext)
  const hmacKey = await _importHmacKey(rawKey);
  const hmacInput = concat(salt, iv, ciphertext);
  const macBuf = await crypto.subtle.sign('HMAC', hmacKey, hmacInput);
  const mac = new Uint8Array(macBuf);

  // Build header: magic (4) + version big-endian uint16 (2)
  const header = new Uint8Array(6);
  header.set(MAGIC, 0);
  header[4] = 0x00;
  header[5] = 0x03; // version 3

  return concat(header, salt, iv, mac, ciphertext);
}

/**
 * Decrypt a .vkdb file buffer and return the JS object.
 * @param {ArrayBuffer|Uint8Array} buffer
 * @param {string} password
 * @returns {Object}
 */
export async function decryptDB(buffer, password) {
  const blob = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  if (blob.length < 6 + 32 + 16 + 32) {
    throw new Error('Fitxer massa curt o corrupte');
  }

  // Check magic
  if (blob[0] !== 0x56 || blob[1] !== 0x4B || blob[2] !== 0x44 || blob[3] !== 0x42) {
    throw new Error('No és un fitxer qmrClau (magic invàlid)');
  }

  // Read version (big-endian uint16)
  const ver = (blob[4] << 8) | blob[5];
  if (ver > DB_VERSION) {
    throw new Error(`Versió ${ver} no suportada`);
  }

  const salt       = blob.slice(6,  38);
  const iv         = blob.slice(38, 54);
  const macStored  = blob.slice(54, 86);
  const ciphertext = blob.slice(86);

  // Derive key
  const rawKey = await _deriveRawKey(password, salt);

  // Verify HMAC before decrypting (encrypt-then-MAC)
  const hmacKey  = await _importHmacKey(rawKey);
  const hmacInput = concat(salt, iv, ciphertext);
  const macCalc  = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, hmacInput));

  // Constant-time comparison
  if (macCalc.length !== macStored.length) {
    throw new Error('Contrasenya incorrecta o fitxer corrupte');
  }
  let diff = 0;
  for (let i = 0; i < macCalc.length; i++) {
    diff |= macCalc[i] ^ macStored[i];
  }
  if (diff !== 0) {
    throw new Error('Contrasenya incorrecta o fitxer corrupte');
  }

  // Decrypt AES-256-CBC (WebCrypto removes PKCS7 padding automatically)
  const aesKey = await _importAesKey(rawKey);
  let plaintextBuf;
  try {
    plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: iv },
      aesKey,
      ciphertext
    );
  } catch (e) {
    throw new Error('Error de desxifrat: fitxer corrupte o contrasenya incorrecta');
  }

  const jsonText = new TextDecoder().decode(plaintextBuf);
  let data;
  try {
    data = JSON.parse(jsonText);
  } catch (e) {
    throw new Error('Error parsejant les dades: fitxer corrupte');
  }

  return { data, ver };
}
