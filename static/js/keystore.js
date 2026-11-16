/**
 * IndexedDB key and contact storage.
 *
 * Specification: docs/PROJECT_MAIN.md section 8 and docs/STEP_05_keys.md.
 *
 * Stores:
 * - `identity`: holds the local user's private and public CryptoKey objects and fingerprint.
 * - `contacts`: holds contacts' public JWKs and fingerprints for TOFU verification.
 * - `seen`: holds hashes of verified message signatures for replay defense (Step 6).
 *
 * IndexedDB supports structured cloning of CryptoKey objects (even non-extractable ones).
 */

const DB_NAME = "e2ee-chat";
const DB_VERSION = 1;

let dbPromise = null;

/**
 * Open (or create) the `e2ee-chat` IndexedDB database.
 * @returns {Promise<IDBDatabase>}
 */
function openDb() {
  if (dbPromise) return dbPromise;

  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains("identity")) {
        db.createObjectStore("identity", { keyPath: "username" });
      }
      if (!db.objectStoreNames.contains("contacts")) {
        db.createObjectStore("contacts", { keyPath: "username" });
      }
      if (!db.objectStoreNames.contains("seen")) {
        db.createObjectStore("seen", { keyPath: "sigHash" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  return dbPromise;
}

/**
 * Retrieve the stored identity for a user.
 *
 * @param {string} username Lowercase username
 * @returns {Promise<{
 *   username: string,
 *   ecdhPrivateKey: CryptoKey,
 *   ecdhPublicKey: CryptoKey,
 *   ecdsaPrivateKey: CryptoKey,
 *   ecdsaPublicKey: CryptoKey,
 *   ecdhJwk: object,
 *   ecdsaJwk: object,
 *   fingerprint: string
 * } | null>}
 */
export async function getIdentity(username) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("identity", "readonly");
    const store = tx.objectStore("identity");
    const req = store.get(username.toLowerCase());
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Save or replace an identity record in IndexedDB.
 *
 * @param {object} identityData Must contain `username`
 * @returns {Promise<void>}
 */
export async function saveIdentity(identityData) {
  const db = await openDb();
  const record = {
    ...identityData,
    username: identityData.username.toLowerCase(),
  };
  return new Promise((resolve, reject) => {
    const tx = db.transaction("identity", "readwrite");
    const store = tx.objectStore("identity");
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/**
 * Delete a user's local identity (e.g., when resetting keys).
 *
 * @param {string} username
 * @returns {Promise<void>}
 */
export async function clearIdentity(username) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("identity", "readwrite");
    const store = tx.objectStore("identity");
    const req = store.delete(username.toLowerCase());
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/**
 * Get contact public key info and fingerprint by username.
 *
 * @param {string} username Contact's lowercase username
 * @returns {Promise<{
 *   username: string,
 *   ecdhJwk: object,
 *   ecdsaJwk: object,
 *   fingerprint: string,
 *   trustedAt: number
 * } | null>}
 */
export async function getContact(username) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("contacts", "readonly");
    const store = tx.objectStore("contacts");
    const req = store.get(username.toLowerCase());
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Save or update contact public keys and fingerprint.
 *
 * @param {object} contactData Must contain `username`
 * @returns {Promise<void>}
 */
export async function saveContact(contactData) {
  const db = await openDb();
  const record = {
    ...contactData,
    username: contactData.username.toLowerCase(),
    trustedAt: contactData.trustedAt || Date.now(),
  };
  return new Promise((resolve, reject) => {
    const tx = db.transaction("contacts", "readwrite");
    const store = tx.objectStore("contacts");
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}
