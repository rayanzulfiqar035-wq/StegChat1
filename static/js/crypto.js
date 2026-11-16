/**
 * Cryptographic operations using the browser's Web Crypto API only.
 *
 * Specification: docs/PROJECT_MAIN.md section 8 and docs/STEP_05_keys.md.
 *
 * SECURITY:
 * - Never export or handle private keys in plaintext (Rule 1).
 * - Private keys are created with extractable: false.
 * - Only the standard Web Crypto API is used; no custom crypto (Rule 5).
 */

const CURVE = "P-256";

/**
 * Generate long-term identity key pairs:
 * - One ECDH P-256 pair for key agreement (usage: deriveBits)
 * - One ECDSA P-256 pair for digital signatures (usages: sign, verify)
 *
 * Both private keys are non-extractable (extractable: false).
 *
 * @returns {Promise<{
 *   ecdh: CryptoKeyPair,
 *   ecdsa: CryptoKeyPair
 * }>}
 */
export async function generateIdentity() {
  // SECURITY: private key is non-extractable; lives only in IndexedDB.
  const ecdh = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: CURVE },
    false, // extractable: false
    ["deriveBits"]
  );

  // SECURITY: private key is non-extractable; lives only in IndexedDB.
  const ecdsa = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: CURVE },
    false, // extractable: false
    ["sign", "verify"]
  );

  return { ecdh, ecdsa };
}

/**
 * Export a public key as a normalized JWK containing exactly {kty, crv, x, y}.
 *
 * @param {CryptoKey} key Public key only
 * @returns {Promise<{kty: string, crv: string, x: string, y: string}>}
 */
export async function exportPublicJwk(key) {
  if (key.type !== "public") {
    throw new Error("SECURITY: exportPublicJwk only permits public keys");
  }
  const jwk = await window.crypto.subtle.exportKey("jwk", key);
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
  };
}

/**
 * Export an uncompressed raw public key (65 bytes: 0x04 || X || Y).
 *
 * @param {CryptoKey} key Public key only
 * @returns {Promise<Uint8Array>}
 */
export async function exportRaw(key) {
  if (key.type !== "public") {
    throw new Error("SECURITY: exportRaw only permits public keys");
  }
  const rawBuf = await window.crypto.subtle.exportKey("raw", key);
  return new Uint8Array(rawBuf);
}

/**
 * Compute the user key fingerprint:
 * SHA-256 of (raw ECDH public key concatenated with raw ECDSA public key).
 * Returns the first 32 hex characters in uppercase, formatted in groups of 4.
 * Example: "ABCD EF01 2345 6789 ABCD EF01 2345 6789"
 *
 * @param {CryptoKey} ecdhPubKey
 * @param {CryptoKey} ecdsaPubKey
 * @returns {Promise<string>}
 */
export async function fingerprint(ecdhPubKey, ecdsaPubKey) {
  const rawEcdh = await exportRaw(ecdhPubKey);
  const rawEcdsa = await exportRaw(ecdsaPubKey);

  const combined = new Uint8Array(rawEcdh.byteLength + rawEcdsa.byteLength);
  combined.set(rawEcdh, 0);
  combined.set(rawEcdsa, rawEcdh.byteLength);

  const hashBuf = await window.crypto.subtle.digest("SHA-256", combined);
  const hashBytes = new Uint8Array(hashBuf);
  let hex = "";
  for (let i = 0; i < hashBytes.length; i++) {
    hex += hashBytes[i].toString(16).padStart(2, "0");
  }
  const hex32 = hex.slice(0, 32).toUpperCase();
  return hex32.match(/.{1,4}/g).join(" ");
}

/**
 * Import a peer's public ECDH JWK into a CryptoKey.
 *
 * @param {{kty: string, crv: string, x: string, y: string}} jwk
 * @returns {Promise<CryptoKey>}
 */
export async function importPeerEcdh(jwk) {
  return window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: CURVE },
    true,
    []
  );
}

/**
 * Import a peer's public ECDSA JWK into a CryptoKey.
 *
 * @param {{kty: string, crv: string, x: string, y: string}} jwk
 * @returns {Promise<CryptoKey>}
 */
export async function importPeerEcdsa(jwk) {
  return window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: CURVE },
    true,
    ["verify"]
  );
}

/**
 * Compute fingerprint directly from normalized peer public JWKs.
 *
 * @param {{kty: string, crv: string, x: string, y: string}} ecdhJwk
 * @param {{kty: string, crv: string, x: string, y: string}} ecdsaJwk
 * @returns {Promise<string>}
 */
export async function fingerprintFromJwks(ecdhJwk, ecdsaJwk) {
  const ecdhPub = await importPeerEcdh(ecdhJwk);
  const ecdsaPub = await importPeerEcdsa(ecdsaJwk);
  return fingerprint(ecdhPub, ecdsaPub);
}
