/** IndexedDB storage for nonextractable identities, contact trust and replays. */
const DB_NAME = "e2ee-chat";
const DB_VERSION = 2;
let dbPromise = null;

function contactKey(owner, username) {
  return `${owner.toLowerCase()}:${username.toLowerCase()}`;
}

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("identity")) db.createObjectStore("identity", { keyPath: "username" });
      if (!db.objectStoreNames.contains("seen")) db.createObjectStore("seen", { keyPath: "sigHash" });
      if (!db.objectStoreNames.contains("contacts")) {
        db.createObjectStore("contacts", { keyPath: "key" });
      } else {
        const oldStore = request.transaction.objectStore("contacts");
        if (oldStore.keyPath !== "key") {
          // SECURITY: preserve existing trust records in an atomic migration.
          // Records predating account scoping need explicit review on use.
          const records = oldStore.getAll();
          records.onsuccess = () => {
            db.deleteObjectStore("contacts");
            const store = db.createObjectStore("contacts", { keyPath: "key" });
            for (const record of records.result) {
              const owner = (record.owner || "").toLowerCase();
              store.put({ ...record, owner, key: contactKey(owner, record.username),
                needsReview: !owner || Boolean(record.needsReview) });
            }
          };
        }
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => { db.close(); dbPromise = null; };
      resolve(db);
    };
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("Close other chat tabs, then reload to update key storage"));
  }).catch((error) => { dbPromise = null; throw error; });
  return dbPromise;
}

async function runStore(name, mode, operation) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(name, mode);
    let result;
    // SECURITY: wait for commit; request success alone is not a durable write.
    tx.oncomplete = () => resolve(result);
    tx.onabort = () => reject(tx.error || new Error("Key storage transaction aborted"));
    tx.onerror = () => reject(tx.error || new Error("Key storage failed"));
    const request = operation(tx.objectStore(name));
    request.onsuccess = () => { result = request.result; };
  });
}

export async function getIdentity(username) {
  return (await runStore("identity", "readonly", (s) => s.get(username.toLowerCase()))) || null;
}
export async function saveIdentity(identity) {
  await runStore("identity", "readwrite", (s) => s.put({ ...identity, username: identity.username.toLowerCase() }));
}
export async function clearIdentity(username) {
  await runStore("identity", "readwrite", (s) => s.delete(username.toLowerCase()));
}
export async function getContact(username, owner = "") {
  const record = await runStore("contacts", "readonly", (s) => s.get(contactKey(owner, username)));
  if (record) return record;
  if (owner) {
    const legacy = await runStore("contacts", "readonly", (s) => s.get(contactKey("", username)));
    if (legacy) return { ...legacy, needsReview: true };
  }
  return null;
}
export async function saveContact(contact) {
  const owner = (contact.owner || "").toLowerCase();
  const username = contact.username.toLowerCase();
  await runStore("contacts", "readwrite", (s) => s.put({ ...contact, username, owner,
    key: contactKey(owner, username), needsReview: false, trustedAt: contact.trustedAt || Date.now() }));
}
export async function hasSeenSignature(sigHash) {
  return Boolean(await runStore("seen", "readonly", (s) => s.get(sigHash)));
}
export async function markSignatureSeen(sigHash) {
  await runStore("seen", "readwrite", (s) => s.put({ sigHash, seenAt: Date.now() }));
}
