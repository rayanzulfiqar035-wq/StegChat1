/** Encrypted text and PNG chat: browser-only keys and explicit contact trust. */
import {
  generateIdentity, exportPublicJwk, fingerprint, fingerprintFromJwks,
  encryptText, encryptStego, assertMessageEnvelope, verifyMessageSignature, assertTimestamp,
  signatureHash, decryptText, decryptStego, importPeerEcdsa, selfTest, sha256Hex,
} from "./crypto.js";
import { loadImage, usage } from "./stego.js";
import { getIdentity, saveIdentity, getContact, saveContact, hasSeenSignature, markSignatureSeen } from "./keystore.js";

if (typeof io !== "function") throw new Error("Socket.IO client not loaded");
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
const element = (id) => document.getElementById(id);
const currentUsername = element("current-username").textContent.trim().toLowerCase();
const recipientInput = element("recipient-input");
const messageInput = element("message-input");
const sendButton = element("send-btn");
const coverInput = element("cover-image");
const maxStegoBytes = Number(document.querySelector(".chat-panel").dataset.maxStegoBytes);
const usedCovers = new Set();
let selectedCover = null, coverSize = null, coverLoading = false, coverTooLarge = false;
let coverRequest = 0;

function updateCoverUsage() {
  coverTooLarge = false;
  element("cover-warning").textContent = "";
  if (coverSize) {
    try {
      // Frame usage includes the 12-byte IV, 16-byte GCM tag and 4-byte length.
      const metrics = usage(new TextEncoder().encode(messageInput.value).length + 28, coverSize.width, coverSize.height);
      element("cover-usage").textContent = `${(metrics.usedFraction * 100).toFixed(2)}% of image bit capacity will be used.`;
      if (metrics.warning) element("cover-warning").textContent = "Above 10% capacity: changes may be easier to detect.";
    } catch {
      coverTooLarge = true;
      element("cover-warning").textContent = "Payload exceeds 50% capacity. Choose a larger PNG or shorter text.";
    }
  }
  updateSendButton();
}

function removeCover() {
  ++coverRequest;
  selectedCover = null; coverSize = null; coverLoading = false; coverTooLarge = false;
  coverInput.value = "";
  element("cover-usage").textContent = "";
  element("cover-warning").textContent = "";
  updateSendButton();
}

coverInput.addEventListener("change", async () => {
  const request = ++coverRequest;
  selectedCover = null; coverSize = null; coverTooLarge = false;
  element("cover-usage").textContent = "";
  element("cover-warning").textContent = "";
  coverLoading = true;
  updateSendButton();
  const file = coverInput.files[0];
  if (!file) { removeCover(); return; }
  try {
    const image = await loadImage(file);
    if (request !== coverRequest) return;
    selectedCover = file;
    coverSize = { width: image.width, height: image.height };
    updateCoverUsage();
  } catch {
    if (request === coverRequest) element("cover-warning").textContent = "Choose an opaque PNG, 256–4096 pixels per side.";
  } finally {
    if (request === coverRequest) coverLoading = false;
    updateSendButton();
  }
});
element("remove-cover").addEventListener("click", removeCover);
messageInput.addEventListener("input", updateCoverUsage);
const selectedRecipient = () => recipientInput.value.trim().toLowerCase();
// SECURITY: stay offline until private identity initialization has completed.
const socket = io({ transports: ["websocket"], autoConnect: false });
const changedContacts = new Map();
let localIdentity = null;
let currentRecipientKeyData = null;
let contactRequest = 0;
let checkingContact = false;
let sending = false;
let settingUpIdentity = false;
let recipientTimer;
let incomingQueue = Promise.resolve();
const rejectedDeliveries = new Map();

async function acknowledge(id) {
  return new Promise((resolve) => {
    socket.timeout(10000).emit("ack_message", { id }, (error, result) => {
      resolve(!error && result?.ok === true);
    });
  });
}

function showRejectedDelivery(id) {
  if (!Number.isSafeInteger(id) || id <= 0 || rejectedDeliveries.has(id)) return;
  const notice = document.createElement("div");
  notice.className = "rejected-delivery";
  const label = document.createElement("p");
  label.textContent = "A message was rejected and remains pending. You can reconnect to retry it or dismiss it permanently.";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn--ghost btn--small";
  button.textContent = "Dismiss rejected message";
  button.addEventListener("click", async () => {
    button.disabled = true;
    // SECURITY: rejected content is removed only by this explicit user action.
    if (await acknowledge(id)) {
      notice.remove();
      rejectedDeliveries.delete(id);
    } else {
      button.disabled = false;
      setStatus("Could not confirm dismissal. Reconnect to check pending messages.", "error");
    }
  });
  notice.append(label, button);
  element("messages-list").appendChild(notice);
  rejectedDeliveries.set(id, notice);
}

function setStatus(text, type = "info") {
  element("chat-status").textContent = text;
  element("chat-status").className = `chat-status chat-status--${type}`;
}
function updateSendButton() {
  sendButton.disabled = !localIdentity || !socket.connected || checkingContact || sending
    || coverLoading || coverTooLarge || (coverInput.files.length > 0 && !selectedCover)
    || !currentRecipientKeyData || currentRecipientKeyData.username !== selectedRecipient()
    || changedContacts.has(selectedRecipient());
}
function showAlert(title, message, actions = []) {
  element("alert-title").textContent = title;
  element("alert-message").textContent = message;
  element("alert-actions").replaceChildren();
  for (const action of actions) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn--primary btn--small";
    button.textContent = action.label;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await action.onClick(); }
      catch { setStatus("Could not complete key setup or trust update. Retry or reload.", "error"); }
      finally { button.disabled = false; }
    });
    element("alert-actions").appendChild(button);
  }
  element("security-alert").classList.remove("is-hidden");
}
function hideAlert() {
  element("security-alert").classList.add("is-hidden");
  element("alert-actions").replaceChildren();
}
function appendMessage(sender, text, isSelf = false, kind = "text") {
  const item = document.createElement("div");
  item.className = `message-item message-item--${isSelf ? "outgoing" : "incoming"}`;
  item.dataset.kind = kind;
  const header = document.createElement("div");
  header.className = "message-header";
  const name = document.createElement("span");
  name.className = "message-sender";
  name.textContent = isSelf ? "You" : sender;
  header.appendChild(name);
  if (kind === "stego") {
    const label = document.createElement("span");
    label.className = "muted";
    label.textContent = "Hidden in PNG";
    header.appendChild(label);
  }
  const body = document.createElement("div");
  body.className = "message-body";
  // SECURITY: user-supplied text is never parsed as markup.
  body.textContent = text;
  item.append(header, body);
  const messages = element("messages-list");
  messages.appendChild(item);
  messages.scrollTop = messages.scrollHeight;
}
function identityKeyPairs(identity) {
  return {
    ecdh: { privateKey: identity.ecdhPrivateKey, publicKey: identity.ecdhPublicKey },
    ecdsa: { privateKey: identity.ecdsaPrivateKey, publicKey: identity.ecdsaPublicKey },
  };
}
async function fetchKeys(username) {
  const response = await fetch(`/api/users/${encodeURIComponent(username)}/keys`);
  if (!response.ok) {
    let code = "lookup_failed";
    if (response.status === 401) code = "session_expired";
    else if (response.status === 429) code = "lookup_limited";
    else if (response.status === 404) {
      const body = await response.json().catch(() => ({}));
      code = body.error === "user has no public keys" ? "keys_missing" : "user_missing";
    }
    const error = new Error("public keys unavailable");
    error.code = code;
    throw error;
  }
  const keys = await response.json();
  if (keys.username !== username) throw new Error("key directory username mismatch");
  return { ...keys, fingerprint: await fingerprintFromJwks(keys.ecdh_jwk, keys.ecdsa_jwk) };
}
async function publishIdentity(identity, reset = false) {
  const response = await fetch("/api/keys", {
    method: reset ? "PUT" : "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
    body: JSON.stringify({ ecdh_jwk: identity.ecdhJwk, ecdsa_jwk: identity.ecdsaJwk }),
  });
  // SECURITY: reconcile a competing POST only if the public identity matches.
  if (!response.ok && (response.status !== 409
    || (await fetchKeys(currentUsername)).fingerprint !== identity.fingerprint)) {
    throw new Error("Public key upload failed; reload to retry safely");
  }
}
function activateIdentity(identity) {
  localIdentity = identity;
  element("my-fingerprint").textContent = identity.fingerprint;
  hideAlert();
  if (!socket.connected) socket.connect();
  updateSendButton();
}
async function createAndUploadIdentity(reset = false) {
  localIdentity = null;
  socket.disconnect();
  updateSendButton();
  setStatus("Generating identity keys...");
  const { ecdh, ecdsa } = await generateIdentity();
  const identity = {
    username: currentUsername,
    ecdhPrivateKey: ecdh.privateKey, ecdhPublicKey: ecdh.publicKey,
    ecdsaPrivateKey: ecdsa.privateKey, ecdsaPublicKey: ecdsa.publicKey,
    ecdhJwk: await exportPublicJwk(ecdh.publicKey), ecdsaJwk: await exportPublicJwk(ecdsa.publicKey),
    fingerprint: await fingerprint(ecdh.publicKey, ecdsa.publicKey),
  };
  // SECURITY: commit private keys before publishing their public halves.
  await saveIdentity(identity);
  await publishIdentity(identity, reset);
  activateIdentity(identity);
}
function showIdentityWarning(title, message) {
  localIdentity = null;
  socket.disconnect();
  element("my-fingerprint").textContent = "KEYS MISSING";
  updateSendButton();
  showAlert(title, message, [{ label: "Reset keys", onClick: async () => {
    try { await createAndUploadIdentity(true); }
    catch {
      showAlert("Key setup incomplete", "Your saved keys have been retained. Reload to check the server and retry safely.", [
        { label: "Retry key setup", onClick: initIdentity },
      ]);
    }
  } }]);
}
async function initIdentity() {
  if (settingUpIdentity) return;
  settingUpIdentity = true;
  const initialize = async () => {
    const response = await fetch("/api/me");
    if (!response.ok) throw new Error("Sign in again to initialize your keys");
    const me = await response.json();
    if (me.username !== currentUsername) throw new Error("Your account changed; reload this page");
    const identity = await getIdentity(currentUsername);
    if (identity) {
      if (!me.has_keys) await publishIdentity(identity);
      else if ((await fetchKeys(currentUsername)).fingerprint !== identity.fingerprint) {
        showIdentityWarning("Identity Keys Changed", "This browser's keys differ from your published keys. Use the browser holding the current keys, or explicitly reset them. Resetting cannot recover older messages.");
        return;
      }
      activateIdentity(identity);
    } else if (!me.has_keys) await createAndUploadIdentity();
    else showIdentityWarning("Identity Keys Missing", "The private keys on this browser are missing. Old or queued messages encrypted to the lost keys cannot be recovered. Reset keys explicitly to receive new messages.");
  };
  try {
    // SECURITY: serialize first-time generation across tabs on this origin.
    if (navigator.locks) await navigator.locks.request(`identity:${currentUsername}`, initialize);
    else await initialize();
  } catch (error) {
    localIdentity = null;
    socket.disconnect();
    setStatus(error.message, "error");
    showAlert("Key setup incomplete", "Keys already saved on this browser are retained. Retry after checking your connection.", [
      { label: "Retry key setup", onClick: initIdentity },
    ]);
  } finally { settingUpIdentity = false; updateSendButton(); }
}
function showKeyChange(username, stored, live) {
  const change = { stored, live };
  changedContacts.set(username, change);
  updateSendButton();
  showAlert("SECURITY WARNING: Key Changed!",
    `Review ${username}'s key before continuing. Stored: ${stored.fingerprint}. Received: ${live.fingerprint}. Compare fingerprints through a separate trusted channel.`, [{
      label: "Trust new key", onClick: async () => {
        // SECURITY: an old warning cannot approve a newer replacement key.
        const latest = await fetchKeys(username);
        if (latest.fingerprint !== live.fingerprint) { showKeyChange(username, stored, latest); return; }
        await saveContact({ owner: currentUsername, username, ecdhJwk: live.ecdh_jwk,
          ecdsaJwk: live.ecdsa_jwk, fingerprint: live.fingerprint });
        // Concurrent receive/send checks may recreate this same warning. The
        // explicit click approves this fingerprint, regardless of warning object.
        if (changedContacts.get(username)?.live.fingerprint === live.fingerprint) {
          changedContacts.delete(username);
        }
        hideAlert();
        if (selectedRecipient() === username) await checkContactKeys(username);
        setStatus("New key trusted. Ask the sender to resend any rejected message.", "success");
        updateSendButton();
      },
    }]);
}
async function trustContact(username, live) {
  const stored = await getContact(username, currentUsername);
  if (stored && (stored.needsReview || stored.fingerprint !== live.fingerprint)) {
    showKeyChange(username, stored, live);
    return false;
  }
  if (!stored) await saveContact({ owner: currentUsername, username,
    ecdhJwk: live.ecdh_jwk, ecdsaJwk: live.ecdsa_jwk, fingerprint: live.fingerprint });
  return !changedContacts.has(username);
}
async function checkContactKeys(username) {
  const request = ++contactRequest;
  currentRecipientKeyData = null;
  checkingContact = true;
  updateSendButton();
  try {
    if (!/^[a-z0-9_]{3,32}$/.test(username)) return null;
    const live = await fetchKeys(username);
    // SECURITY: discard responses for obsolete selections before trusting them.
    if (request !== contactRequest || selectedRecipient() !== username) return null;
    if (!(await trustContact(username, live))) return null;
    if (request !== contactRequest || selectedRecipient() !== username) return null;
    currentRecipientKeyData = live;
    if (element("alert-title").textContent === "Contact keys unavailable") hideAlert();
    element("contact-fingerprint").textContent = live.fingerprint;
    element("contact-security-bar").classList.remove("is-hidden");
    return live;
  } catch (error) {
    if (request === contactRequest && selectedRecipient() === username) {
      // SECURITY: use fixed explanations, never reflect arbitrary error bodies.
      const messages = {
        keys_missing: "This contact has not set up their encryption keys. Ask them to sign in and open Chat, then retry here.",
        user_missing: "No account has that username. Check the exact recipient username.",
        session_expired: "Your session has expired. Sign in again to look up contact keys.",
        lookup_limited: "Too many public-key lookups. Wait a minute, then retry.",
      };
      const message = messages[error.code] || "Could not verify this contact's public keys. Check your connection and retry.";
      setStatus(message, "error");
      showAlert("Contact keys unavailable", message, [{
        label: "Retry contact lookup",
        onClick: async () => {
          if (await checkContactKeys(selectedRecipient())) hideAlert();
        },
      }]);
    }
    return null;
  } finally {
    if (request === contactRequest) checkingContact = false;
    updateSendButton();
  }
}
recipientInput.addEventListener("input", () => {
  clearTimeout(recipientTimer);
  ++contactRequest;
  checkingContact = false;
  currentRecipientKeyData = null;
  element("contact-security-bar").classList.add("is-hidden");
  updateSendButton();
  if (localIdentity) recipientTimer = setTimeout(() => checkContactKeys(selectedRecipient()), 300);
});
socket.on("connect", () => { setStatus("Connected to chat server", "success"); updateSendButton(); });
socket.on("disconnect", () => { setStatus("Disconnected from chat server", "error"); updateSendButton(); });
socket.on("connect_error", () => { setStatus("Connection failed. Check HTTPS and sign in again.", "error"); updateSendButton(); });
async function handleIncoming(payload) {
  if (!localIdentity) throw new Error("local identity unavailable");
  if (!Number.isSafeInteger(payload?.id) || payload.id <= 0) throw new Error("invalid delivery id");
  if (payload?.kind === "stego" && (typeof payload.img !== "string"
    || payload.img.length > 4 * Math.ceil(maxStegoBytes / 3))) throw new Error("image too large");
  const env = assertMessageEnvelope(payload);
  if (env.recipient !== currentUsername) throw new Error("not for this user");
  // SECURITY: TOFU, signature, timestamp, replay, decrypt, render, record seen.
  const keys = await fetchKeys(env.sender);
  if (!(await trustContact(env.sender, keys))) throw new Error("sender key requires explicit trust");
  await verifyMessageSignature(env, await importPeerEcdsa(keys.ecdsa_jwk));
  assertTimestamp(env.ts);
  const hash = `${currentUsername}:${await signatureHash(env.sig)}`;
  if (await hasSeenSignature(hash)) {
    // SECURITY: an already rendered delivery can be acknowledged again after
    // a lost acknowledgment, without decrypting or rendering it twice.
    await acknowledge(payload.id);
    setStatus("Duplicate skipped: replayed message");
    return;
  }
  const text = await (env.kind === "stego" ? decryptStego : decryptText)({ ownEcdhPrivateKey: localIdentity.ecdhPrivateKey, env });
  appendMessage(env.sender, text, false, env.kind);
  await markSignatureSeen(hash);
  rejectedDeliveries.get(payload.id)?.remove();
  rejectedDeliveries.delete(payload.id);
  await acknowledge(payload.id);
}
socket.on("message", (payload) => {
  // SECURITY: serialize deliveries so duplicates cannot race within this tab.
  incomingQueue = incomingQueue.then(async () => {
    try { await handleIncoming(payload); }
    catch (error) {
      const reasons = new Set(["replayed message", "message too old", "timestamp in the future",
        "bad signature", "not for this user", "sender key requires explicit trust"]);
      setStatus(`Message rejected: ${reasons.has(error.message) ? error.message : "validation or decryption failed"}`, "error");
      showRejectedDelivery(payload?.id);
    }
  });
});
element("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (sending) return;
  if (coverLoading || coverTooLarge || (coverInput.files.length && !selectedCover)) {
    setStatus("Choose a valid cover image and keep usage at or below 50%.", "error");
    return;
  }
  const recipient = selectedRecipient();
  const text = messageInput.value;
  const cover = selectedCover, attachment = coverRequest;
  if (!/^[a-z0-9_]{3,32}$/.test(recipient) || !text.trim() || text.length > 2000) {
    setStatus("Enter a valid recipient and a message of 1–2000 characters.", "error");
    return;
  }
  if (!localIdentity || !socket.connected) {
    setStatus("Wait for identity setup and a connection before sending.", "error");
    return;
  }
  sending = true;
  updateSendButton();
  try {
    clearTimeout(recipientTimer);
    // SECURITY: recheck the contact on each send to catch resets without typing.
    const keys = await checkContactKeys(recipient);
    if (!keys || selectedRecipient() !== recipient || changedContacts.has(recipient)) return;
    const identity = localIdentity;
    setStatus("Encrypting...");
    let coverHash;
    if (cover) {
      coverHash = await sha256Hex(await cover.arrayBuffer());
      if (usedCovers.has(coverHash)) {
        element("cover-warning").textContent = "This cover was already used. Choose a fresh image.";
        return;
      }
    }
    const params = { ownIdentity: identityKeyPairs(identity), recipientEcdhJwk: keys.ecdh_jwk,
      sender: currentUsername, recipient, text };
    const result = cover ? await encryptStego({ ...params, coverBlob: cover, maxStegoBytes }) : null;
    const envelope = result ? result.envelope : await encryptText(params);
    if (selectedRecipient() !== recipient || localIdentity !== identity
      || currentRecipientKeyData !== keys || changedContacts.has(recipient) || attachment !== coverRequest) return;
    // SECURITY: reserve a cover before emitting, including uncertain delivery.
    if (coverHash) usedCovers.add(coverHash);
    const ack = await new Promise((resolve, reject) => {
      socket.timeout(10000).emit("send_message", envelope, (error, response) => {
        if (error) reject(new Error("send timed out")); else resolve(response);
      });
    });
    if (!ack?.ok) {
      // Even a rejected envelope transmitted a carrier; keep it reserved.
      if (coverHash) element("cover-warning").textContent = "This cover was transmitted. Choose a fresh image for another attempt.";
      const reasons = new Set(["queue_full", "rate_limited", "recipient not found", "message too large", "image too large", "unauthorized"]);
      setStatus(`Message not sent: ${reasons.has(ack?.error) ? ack.error : "server rejected the envelope"}`, "error");
      return;
    }
    appendMessage(currentUsername, text, true, envelope.kind);
    if (cover && selectedCover === cover) removeCover();
    setStatus("Message sent", "success");
    if (messageInput.value === text) messageInput.value = "";
    messageInput.focus();
  } catch (error) {
    setStatus(error.message === "image too large"
      ? `Stego PNG exceeds the ${(maxStegoBytes / 1048576).toFixed(2)} MiB image limit. Choose a smaller cover.`
      : "Could not confirm sending. Check the image and connection before retrying.", "error");
  }
  finally { sending = false; updateSendButton(); }
});
// Browser console acceptance check: console.table(await e2ee.selfTest()).
window.e2ee = { socket, selfTest: async (options = {}) => {
  const identity = localIdentity || (await getIdentity(currentUsername));
  return selfTest({ identity: identity ? identityKeyPairs(identity) : undefined, ...options });
} };
updateSendButton();
initIdentity();
