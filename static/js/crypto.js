/**
 * Cryptographic operations using the browser's Web Crypto API only.
 *
 * Specification: docs/PROJECT_MAIN.md section 8, docs/STEP_05_keys.md and
 * docs/STEP_06_encryption.md.
 *
 * SECURITY:
 * - Never export or handle private keys in plaintext (Rule 1).
 * - Private keys are created with extractable: false.
 * - Only the standard Web Crypto API is used; no custom crypto (Rule 5).
 * - The only random source is `crypto.getRandomValues` (Rule 4).
 * - A fresh ephemeral key pair and a fresh IV are created per message (§8).
 */

import { embed, extract } from "./stego.js";

const CURVE = "P-256";

// §8 KDF labels: never reuse one derived value for two purposes.
const KDF_LABEL_TEXT = "message-encryption";
const KDF_SALT = new Uint8Array(32); // 32 zero bytes
const HKDF_PARAMS = { name: "HKDF", hash: "SHA-256", salt: KDF_SALT };

const IV_BYTES = 12;
const ECDH_BITS = 256;

// §12 envelope protocol version.
const PROTOCOL_VERSION = 1;

// §8 receive window for `ts`.
const MAX_TS_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_TS_FUTURE_MS = 5 * 60 * 1000; // 5 minutes

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/**
 * Standard base64 (not base64url) with padding, as used on the wire (§8).
 *
 * @param {ArrayBuffer | Uint8Array} bytes
 * @returns {string}
 */
export function toB64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  // SECURITY: build the string in chunks to avoid blowing the argument limit
  // when handling large stego payloads.
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < view.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, view.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/**
 * Decode standard base64 with padding, failing closed on malformed input.
 *
 * @param {string} value
 * @returns {Uint8Array}
 */
export function fromB64(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) {
    throw new Error("malformed base64");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("malformed base64");
  }
  const binary = atob(value);
  if (btoa(binary) !== value) throw new Error("malformed base64");
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * SHA-256 of a byte array, returned as lowercase hex.
 *
 * @param {ArrayBuffer | Uint8Array} bytes
 * @returns {Promise<string>}
 */
export async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await window.crypto.subtle.digest("SHA-256", bytes)));
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

// ---------------------------------------------------------------------------
// Long-term identity keys (Step 5)
// ---------------------------------------------------------------------------

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

/**
 * Convert a raw uncompressed P-256 public point (base64) into a JWK.
 *
 * @param {string} rawB64
 * @returns {{kty: string, crv: string, x: string, y: string}}
 */
function jwkFromRawB64(rawB64) {
  const raw = fromB64(rawB64);
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error("invalid ephemeral public key");
  }
  const b64url = (bytes) => {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  return { kty: "EC", crv: CURVE, x: b64url(raw.slice(1, 33)), y: b64url(raw.slice(33, 65)) };
}

// ---------------------------------------------------------------------------
// Key derivation (§8): ephemeral ECDH -> HKDF-SHA256 -> AES-256-GCM
// ---------------------------------------------------------------------------

/**
 * Derive the AES-GCM key for one message.
 *
 * @param {CryptoKey} privateKey ECDH private key (own long-term or ephemeral)
 * @param {CryptoKey} publicKey ECDH public key of the other party
 * @param {string} label HKDF info label
 * @returns {Promise<CryptoKey>}
 */
async function deriveAesKey(privateKey, publicKey, label) {
  return derivePurposeAes(await deriveHkdfKey(privateKey, publicKey), label);
}

async function deriveHkdfKey(privateKey, publicKey) {
  // Raw ECDH output is never used as a key directly (§8).
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    ECDH_BITS
  );
  return window.crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey", "deriveBits"]);
}

async function derivePurposeAes(hkdfKey, label) {
  // SECURITY: HKDF with a fixed salt, a purpose label and SHA-256 separates the
  // encryption key from the raw shared secret, so the ECDH output itself is
  // never usable as a key (prevents related-key attacks and key reuse).
  return window.crypto.subtle.deriveKey(
    { ...HKDF_PARAMS, info: utf8(label) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveStegoKeys(privateKey, publicKey) {
  const shared = await deriveHkdfKey(privateKey, publicKey);
  // SECURITY: derive independent purposes from the same ECDH secret. The raw
  // positions key stays in browser memory and is never sent with the envelope.
  return {
    aesKey: await derivePurposeAes(shared, KDF_LABEL_TEXT),
    stegoKey: new Uint8Array(await crypto.subtle.deriveBits(
      { ...HKDF_PARAMS, info: utf8("stego-positions") }, shared, 256)),
  };
}

/**
 * AES-GCM additional data, UTF-8 of `v1|<kind>|<sender>|<recipient>|<ts>` (§8).
 *
 * @param {string} kind
 * @param {string} sender
 * @param {string} recipient
 * @param {number} ts
 * @returns {Uint8Array}
 */
function additionalData(kind, sender, recipient, ts) {
  return utf8(`v${PROTOCOL_VERSION}|${kind}|${sender}|${recipient}|${ts}`);
}

/**
 * Bytes covered by the signature for text messages (§8):
 * UTF-8 of JSON.stringify(["v1","text",sender,recipient,ts,eph,iv,ct]).
 *
 * @param {object} env
 * @returns {Uint8Array}
 */
export function textSigningBytes(env) {
  return utf8(
    JSON.stringify([
      `v${PROTOCOL_VERSION}`,
      "text",
      env.sender,
      env.recipient,
      env.ts,
      env.eph,
      env.iv,
      env.ct,
    ])
  );
}

/**
 * Bytes covered by the signature for stego messages (§8). Used from Step 9.
 *
 * @param {object} env
 * @param {string} pngSha256Hex
 * @returns {Uint8Array}
 */
export function stegoSigningBytes(env, pngSha256Hex) {
  return utf8(
    JSON.stringify([
      `v${PROTOCOL_VERSION}`,
      "stego",
      env.sender,
      env.recipient,
      env.ts,
      env.eph,
      pngSha256Hex,
    ])
  );
}

// ---------------------------------------------------------------------------
// Encrypt + sign
// ---------------------------------------------------------------------------

/**
 * Encrypt a text message to a recipient and sign the envelope fields.
 *
 * @param {object} params
 * @param {{ecdh: CryptoKeyPair, ecdsa: CryptoKeyPair}} params.ownIdentity Sender's key pairs
 * @param {{kty: string, crv: string, x: string, y: string}} params.recipientEcdhJwk
 * @param {string} params.sender Lowercase username
 * @param {string} params.recipient Lowercase username
 * @param {string} params.text Plaintext, used in memory only
 * @returns {Promise<object>} Text envelope (§12)
 */
export async function encryptText({ ownIdentity, recipientEcdhJwk, sender, recipient, text }) {
  const recipientPublic = await importPeerEcdh(recipientEcdhJwk);

  // SECURITY: use a separate ephemeral pair per message and discard it after
  // use. This does not provide forward secrecy for the recipient's identity.
  const ephemeral = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: CURVE },
    false,
    ["deriveBits"]
  );

  const aesKey = await deriveAesKey(ephemeral.privateKey, recipientPublic, KDF_LABEL_TEXT);
  const eph = toB64(await exportRaw(ephemeral.publicKey));
  // SECURITY: a fresh random IV for every encryption; never reused (§8).
  const ivBytes = window.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ts = Date.now();

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: ivBytes,
      tagLength: 128,
      additionalData: additionalData("text", sender, recipient, ts),
    },
    aesKey,
    utf8(text)
  );

  const env = {
    v: PROTOCOL_VERSION,
    kind: "text",
    sender,
    recipient,
    ts,
    eph,
    iv: toB64(ivBytes),
    ct: toB64(ciphertext),
  };

  // SECURITY: every message is signed over the exact base64 strings that travel
  // on the wire, so the server cannot alter any field unnoticed (§8).
  const signature = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    ownIdentity.ecdsa.privateKey,
    textSigningBytes(env)
  );

  return { ...env, sig: toB64(signature) };
}

export async function encryptStego({ ownIdentity, recipientEcdhJwk, sender, recipient, text,
  coverBlob, maxStegoBytes = 3145728 }) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: CURVE }, false, ["deriveBits"]);
  const { aesKey, stegoKey } = await deriveStegoKeys(ephemeral.privateKey, await importPeerEcdh(recipientEcdhJwk));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const env = { v: 1, kind: "stego", sender, recipient, ts: Date.now(),
    eph: toB64(await exportRaw(ephemeral.publicKey)) };
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv,
    tagLength: 128, additionalData: additionalData("stego", sender, recipient, env.ts) }, aesKey, utf8(text)));
  const payload = new Uint8Array(iv.length + ciphertext.length);
  payload.set(iv); payload.set(ciphertext, iv.length);
  let image;
  try { image = await embed(coverBlob, payload, stegoKey); }
  finally { stegoKey.fill(0); }
  if (image.blob.size > maxStegoBytes) throw new Error("image too large");
  const png = new Uint8Array(await image.blob.arrayBuffer());
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    ownIdentity.ecdsa.privateKey, stegoSigningBytes(env, await sha256Hex(png)));
  return { envelope: { ...env, img: toB64(png), sig: toB64(signature) },
    usedFraction: image.usedFraction, warning: image.warning, changedChannels: image.changedChannels };
}

// ---------------------------------------------------------------------------
// Verify + decrypt
// ---------------------------------------------------------------------------

/**
 * Validate that a decoded envelope is a structural text envelope (§12).
 *
 * @param {any} env
 * @returns {object}
 */
export function assertTextEnvelope(env) {
  if (env?.kind !== "text") throw new Error("unsupported kind");
  return assertMessageEnvelope(env);
}

export function assertMessageEnvelope(env) {
  if (!env || typeof env !== "object" || Array.isArray(env)) {
    throw new Error("invalid envelope");
  }
  if (env.v !== PROTOCOL_VERSION) throw new Error("unsupported version");
  if (!["text", "stego"].includes(env.kind)) throw new Error("unsupported kind");
  for (const field of ["sender", "recipient", "eph", "sig", ...(env.kind === "text" ? ["iv", "ct"] : ["img"])]) {
    if (typeof env[field] !== "string" || env[field].length === 0) {
      throw new Error("invalid envelope");
    }
  }
  if (!Number.isSafeInteger(env.ts) || env.ts <= 0) throw new Error("invalid envelope");
  // SECURITY: usernames are normalised server-side to [a-z0-9_]{3,32}, so any
  // other shape in the envelope is refused before any fetch or crypto work.
  for (const name of [env.sender, env.recipient]) {
    if (!/^[a-z0-9_]{3,32}$/.test(name)) throw new Error("invalid envelope");
  }
  // Reject non-canonical base64 early (cheap, before any crypto work).
  const ephemeral = fromB64(env.eph);
  if (ephemeral.length !== 65 || ephemeral[0] !== 0x04) throw new Error("invalid ephemeral key");
  if (env.kind === "text") {
    if (fromB64(env.iv).length !== 12) throw new Error("invalid iv");
    if (fromB64(env.ct).length < 16) throw new Error("invalid ciphertext");
  } else {
    const png = fromB64(env.img);
    if (![137,80,78,71,13,10,26,10].every((b, i) => png[i] === b)) throw new Error("invalid PNG");
  }
  if (fromB64(env.sig).length !== 64) throw new Error("invalid signature");
  return env;
}

/**
 * Verify an envelope signature with the sender's long-term ECDSA key.
 * MUST be called before decrypting or rendering anything (§8 receive order).
 *
 * @param {object} env
 * @param {CryptoKey} senderEcdsaPub
 * @returns {Promise<void>} Rejects when the signature is invalid
 */
export async function verifyTextSignature(env, senderEcdsaPub) {
  const ok = await window.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    senderEcdsaPub,
    fromB64(env.sig),
    textSigningBytes(env)
  );
  if (!ok) throw new Error("bad signature");
}

export async function verifyMessageSignature(env, senderEcdsaPub) {
  if (env.kind === "text") return verifyTextSignature(env, senderEcdsaPub);
  // SECURITY: authenticate every PNG byte before Canvas decoding/extraction.
  const hash = await sha256Hex(fromB64(env.img));
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, senderEcdsaPub,
    fromB64(env.sig), stegoSigningBytes(env, hash));
  if (!ok) throw new Error("bad signature");
}

/**
 * SHA-256 of the signature, used as the replay-defence key in the `seen` store.
 *
 * @param {string} sigB64
 * @returns {Promise<string>}
 */
export async function signatureHash(sigB64) {
  return sha256Hex(fromB64(sigB64));
}

/**
 * Check `ts`: not older than 7 days and not more than 5 minutes in the future.
 *
 * @param {number} ts
 * @param {number} [now]
 * @returns {void}
 */
export function assertTimestamp(ts, now = Date.now()) {
  if (!Number.isSafeInteger(ts) || ts <= 0) throw new Error("invalid timestamp");
  if (ts < now - MAX_TS_AGE_MS) throw new Error("message too old");
  if (ts > now + MAX_TS_FUTURE_MS) throw new Error("timestamp in the future");
}

/**
 * Decrypt an already-verified text envelope.
 *
 * @param {object} params
 * @param {CryptoKey} params.ownEcdhPrivateKey
 * @param {object} params.env Verified envelope
 * @returns {Promise<string>} Plaintext, in memory only
 */
export async function decryptText({ ownEcdhPrivateKey, env }) {
  const ephPublic = await importPeerEcdh(jwkFromRawB64(env.eph));
  const aesKey = await deriveAesKey(ownEcdhPrivateKey, ephPublic, KDF_LABEL_TEXT);
  const plainBuf = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: fromB64(env.iv),
      tagLength: 128,
      // SECURITY: binding sender/recipient/ts into the AAD makes any change to
      // those fields a decryption failure, not just a display issue.
      additionalData: additionalData(env.kind, env.sender, env.recipient, env.ts),
    },
    aesKey,
    fromB64(env.ct)
  );
  return new TextDecoder().decode(plainBuf);
}

export async function decryptStego({ ownEcdhPrivateKey, env }) {
  const { aesKey, stegoKey } = await deriveStegoKeys(ownEcdhPrivateKey,
    await importPeerEcdh(jwkFromRawB64(env.eph)));
  let payload;
  try { payload = await extract(new Blob([fromB64(env.img)], { type: "image/png" }), stegoKey); }
  finally { stegoKey.fill(0); }
  if (payload.length < 28) throw new Error("invalid encrypted payload");
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: payload.slice(0, 12),
    tagLength: 128, additionalData: additionalData("stego", env.sender, env.recipient, env.ts) },
    aesKey, payload.slice(12));
  return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}

// ---------------------------------------------------------------------------
// Self-test (Step 6, task 12)
// ---------------------------------------------------------------------------

class MemorySeenStore {
  constructor() {
    this.hashes = new Set();
  }

  async has(hash) {
    return this.hashes.has(hash);
  }

  async add(hash) {
    this.hashes.add(hash);
  }
}

/**
 * End-to-end self-test, callable from the browser console:
 *
 *   const { selfTest } = await import("/static/js/crypto.js");
 *   console.table(await selfTest());
 *
 * Encrypts to its own public key and decrypts, then confirms that tampering
 * with the envelope, identity fields, timestamp or signature fails.
 *
 * @param {object} [options]
 * @param {{ecdh: CryptoKeyPair, ecdsa: CryptoKeyPair}} [options.identity] Generated when absent
 * @param {string} [options.sender]
 * @param {string} [options.recipient]
 * @returns {Promise<Array<{case: string, expected: string, passed: boolean, got: string}>>}
 */
export async function selfTest(options = {}) {
  const identity = options.identity || (await generateIdentity());
  const sender = options.sender || "selftest_sender";
  const recipient = options.recipient || "selftest_recipient";
  const ecdhJwk = await exportPublicJwk(identity.ecdh.publicKey);
  const ecdsaJwk = await exportPublicJwk(identity.ecdsa.publicKey);
  const senderEcdsaPub = await importPeerEcdsa(ecdsaJwk);

  const runCase = async (name, expectRejection, fn) => {
    try {
      await fn();
      return {
        case: name,
        expected: expectRejection ? "rejected" : "accepted",
        passed: !expectRejection,
        got: "accepted",
      };
    } catch (err) {
      return {
        case: name,
        expected: expectRejection ? "rejected" : "accepted",
        passed: expectRejection,
        got: `rejected: ${err.message}`,
      };
    }
  };

  const text = "self-test message ✓";
  const baseEnv = await encryptText({
    ownIdentity: identity,
    recipientEcdhJwk: ecdhJwk,
    sender,
    recipient,
    text,
  });

  // Exercise the crypto receive order with a known self-test identity.
  const receive = async (env, seen, senderKey = senderEcdsaPub) => {
    const checked = assertTextEnvelope(env);
    await verifyTextSignature(checked, senderKey);
    assertTimestamp(checked.ts);
    const hash = await signatureHash(checked.sig);
    if (await seen.has(hash)) throw new Error("replay");
    const plain = await decryptText({ ownEcdhPrivateKey: identity.ecdh.privateKey, env: checked });
    await seen.add(hash);
    return plain;
  };

  const results = [];

  results.push(
    await runCase("normal message decrypts", false, async () => {
      const plain = await receive(baseEnv, new MemorySeenStore());
      if (plain !== text) throw new Error("plaintext mismatch");
    })
  );

  results.push(
    await runCase("flipped ciphertext byte fails", true, async () => {
      const bytes = fromB64(baseEnv.ct);
      bytes[Math.floor(bytes.length / 2)] ^= 0x01;
      await receive({ ...baseEnv, ct: toB64(bytes) }, new MemorySeenStore());
    })
  );

  results.push(
    await runCase("changed sender fails", true, async () => {
      await receive({ ...baseEnv, sender: "mallory" }, new MemorySeenStore());
    })
  );

  results.push(
    await runCase("changed recipient fails", true, async () => {
      await receive({ ...baseEnv, recipient: "mallory" }, new MemorySeenStore());
    })
  );

  results.push(
    await runCase("changed timestamp fails", true, async () => {
      await receive({ ...baseEnv, ts: baseEnv.ts + 1000 }, new MemorySeenStore());
    })
  );

  results.push(
    await runCase("wrong signature fails", true, async () => {
      // A valid signature from a different key over the same bytes.
      const other = await generateIdentity();
      const forgedSig = await window.crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        other.ecdsa.privateKey,
        textSigningBytes(baseEnv)
      );
      await receive({ ...baseEnv, sig: toB64(forgedSig) }, new MemorySeenStore());
    })
  );

  results.push(
    await runCase("identical envelope replay is dropped", true, async () => {
      const seen = new MemorySeenStore();
      await receive(baseEnv, seen);
      await receive(baseEnv, seen);
    })
  );

  results.push(
    await runCase("timestamp 8 days old fails", true, async () => assertTimestamp(Date.now() - 8 * 24 * 60 * 60 * 1000))
  );

  results.push(
    await runCase("timestamp 10 minutes ahead fails", true, async () => assertTimestamp(Date.now() + 10 * 60 * 1000))
  );

  return results;
}
