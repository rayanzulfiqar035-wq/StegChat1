/**
 * Real-time chat client with Key Management & TOFU (Step 5).
 *
 * Cryptography: Web Crypto API via crypto.js.
 * Storage: IndexedDB via keystore.js.
 *
 * SECURITY:
 * - Private keys are non-extractable and never leave IndexedDB (Rule 1).
 * - DOM manipulation strictly uses textContent / createTextNode (Rule 7).
 * - Rejects any inline scripts, inline styles, or external CDN dependencies.
 */

import {
  generateIdentity,
  exportPublicJwk,
  fingerprint,
  fingerprintFromJwks,
} from "./crypto.js";

import {
  getIdentity,
  saveIdentity,
  clearIdentity,
  getContact,
  saveContact,
} from "./keystore.js";

// Read CSRF token from base template meta tag for state-changing requests
const csrfMeta = document.querySelector('meta[name="csrf-token"]');
const CSRF_TOKEN = csrfMeta ? csrfMeta.getAttribute("content") : "";

// Connect strictly using WebSockets over the current secure origin (WSS).
const socket = io({
  transports: ["websocket"],
});

const currentUsernameElem = document.getElementById("current-username");
const currentUsername = currentUsernameElem ? currentUsernameElem.textContent.trim().toLowerCase() : "";

const myFingerprintElem = document.getElementById("my-fingerprint");
const securityAlert = document.getElementById("security-alert");
const alertTitle = document.getElementById("alert-title");
const alertMessage = document.getElementById("alert-message");
const alertActions = document.getElementById("alert-actions");

const contactSecurityBar = document.getElementById("contact-security-bar");
const contactFingerprintElem = document.getElementById("contact-fingerprint");

const messagesList = document.getElementById("messages-list");
const chatStatus = document.getElementById("chat-status");
const chatForm = document.getElementById("chat-form");
const recipientInput = document.getElementById("recipient-input");
const messageInput = document.getElementById("message-input");
const sendBtn = document.getElementById("send-btn");

let localIdentity = null;
let currentRecipientKeyData = null;
let isSendingBlocked = false;

// ---------------------------------------------------------------------------
// UI Alerts & Notifications
// ---------------------------------------------------------------------------

function setStatus(text, type = "info") {
  if (!chatStatus) return;
  chatStatus.textContent = text;
  chatStatus.className = `chat-status chat-status--${type}`;
}

function showAlert(title, message, actions = []) {
  if (!securityAlert) return;
  alertTitle.textContent = title;
  alertMessage.textContent = message;

  // Clear previous actions
  alertActions.replaceChildren();

  actions.forEach((act) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = act.className || "btn btn--primary btn--small";
    btn.textContent = act.label;
    btn.addEventListener("click", act.onClick);
    alertActions.appendChild(btn);
  });

  securityAlert.classList.remove("is-hidden");
}

function hideAlert() {
  if (!securityAlert) return;
  securityAlert.classList.add("is-hidden");
  alertActions.replaceChildren();
}

function appendMessage(sender, text, isSelf) {
  if (!messagesList) return;

  const item = document.createElement("div");
  item.className = `message-item ${isSelf ? "message-item--outgoing" : "message-item--incoming"}`;

  const header = document.createElement("div");
  header.className = "message-header";

  const senderSpan = document.createElement("span");
  senderSpan.className = "message-sender";
  senderSpan.textContent = isSelf ? "You" : sender;
  header.appendChild(senderSpan);

  const body = document.createElement("div");
  body.className = "message-body";
  body.textContent = text; // SECURITY: textContent prevents HTML injection / XSS

  item.appendChild(header);
  item.appendChild(body);
  messagesList.appendChild(item);

  messagesList.scrollTop = messagesList.scrollHeight;
}

// ---------------------------------------------------------------------------
// Identity Initialization & Key Management (Step 5)
// ---------------------------------------------------------------------------

async function createAndUploadIdentity(isReset = false) {
  setStatus("Generating cryptographic identity...", "info");
  const { ecdh, ecdsa } = await generateIdentity();

  const ecdhJwk = await exportPublicJwk(ecdh.publicKey);
  const ecdsaJwk = await exportPublicJwk(ecdsa.publicKey);
  const fp = await fingerprint(ecdh.publicKey, ecdsa.publicKey);

  const identityData = {
    username: currentUsername,
    ecdhPrivateKey: ecdh.privateKey,
    ecdhPublicKey: ecdh.publicKey,
    ecdsaPrivateKey: ecdsa.privateKey,
    ecdsaPublicKey: ecdsa.publicKey,
    ecdhJwk,
    ecdsaJwk,
    fingerprint: fp,
  };

  // Upload normalized public keys to server
  const endpoint = "/api/keys";
  const method = isReset ? "PUT" : "POST";

  const res = await fetch(endpoint, {
    method: method,
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": CSRF_TOKEN,
    },
    body: JSON.stringify({
      ecdh_jwk: ecdhJwk,
      ecdsa_jwk: ecdsaJwk,
    }),
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.error || `Failed to upload keys (HTTP ${res.status})`);
  }

  // Persist non-extractable keys in IndexedDB only after server upload succeeds
  await saveIdentity(identityData);
  localIdentity = identityData;

  if (myFingerprintElem) {
    myFingerprintElem.textContent = fp;
  }
  hideAlert();
  setStatus("Identity keys ready", "success");
}

async function initIdentity() {
  if (!currentUsername) return;

  try {
    // 1. Check server status
    const meRes = await fetch("/api/me");
    if (!meRes.ok) throw new Error("Failed to check user key status");
    const meData = await meRes.json();

    // 2. Check local IndexedDB store
    const local = await getIdentity(currentUsername);

    if (local) {
      localIdentity = local;
      if (myFingerprintElem) {
        myFingerprintElem.textContent = local.fingerprint;
      }
    } else if (!meData.has_keys) {
      // First login: generate and POST /api/keys
      await createAndUploadIdentity(false);
    } else {
      // Local keys missing, but server has keys: warn user and offer reset
      if (myFingerprintElem) {
        myFingerprintElem.textContent = "KEYS MISSING";
      }
      showAlert(
        "Identity Keys Missing",
        "Your cryptographic keys were not found on this device. Any unread messages cannot be decrypted. You can reset your keys to generate a new pair.",
        [
          {
            label: "Reset Keys",
            className: "btn btn--primary btn--small",
            onClick: async () => {
              try {
                await createAndUploadIdentity(true);
              } catch (err) {
                showAlert("Key Reset Failed", err.message);
              }
            },
          },
        ]
      );
    }
  } catch (err) {
    setStatus(`Identity error: ${err.message}`, "error");
  }
}

// ---------------------------------------------------------------------------
// Contact Verification & TOFU (Trust On First Use)
// ---------------------------------------------------------------------------

async function checkContactKeys(recipient) {
  if (!recipient || recipient.length < 3) {
    if (contactSecurityBar) contactSecurityBar.classList.add("is-hidden");
    currentRecipientKeyData = null;
    isSendingBlocked = false;
    if (sendBtn) sendBtn.disabled = false;
    hideAlert();
    return;
  }

  try {
    const res = await fetch(`/api/users/${encodeURIComponent(recipient)}/keys`);
    if (res.status === 404) {
      if (contactSecurityBar) contactSecurityBar.classList.add("is-hidden");
      currentRecipientKeyData = null;
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const keyData = await res.json();
    const liveFingerprint = await fingerprintFromJwks(keyData.ecdh_jwk, keyData.ecdsa_jwk);

    // Check stored contact in IndexedDB
    const stored = await getContact(recipient);

    if (!stored) {
      // First encounter (TOFU): store and display
      await saveContact({
        username: recipient,
        ecdhJwk: keyData.ecdh_jwk,
        ecdsaJwk: keyData.ecdsa_jwk,
        fingerprint: liveFingerprint,
      });

      if (contactFingerprintElem) contactFingerprintElem.textContent = liveFingerprint;
      if (contactSecurityBar) contactSecurityBar.classList.remove("is-hidden");
      isSendingBlocked = false;
      if (sendBtn) sendBtn.disabled = false;
      hideAlert();
    } else if (stored.fingerprint === liveFingerprint) {
      // Fingerprint matches stored key
      if (contactFingerprintElem) contactFingerprintElem.textContent = liveFingerprint;
      if (contactSecurityBar) contactSecurityBar.classList.remove("is-hidden");
      isSendingBlocked = false;
      if (sendBtn) sendBtn.disabled = false;
      hideAlert();
    } else {
      // SECURITY WARNING: Fingerprint mismatch!
      isSendingBlocked = true;
      if (sendBtn) sendBtn.disabled = true;

      if (contactFingerprintElem) {
        contactFingerprintElem.textContent = `${liveFingerprint} (CHANGED!)`;
      }
      if (contactSecurityBar) contactSecurityBar.classList.remove("is-hidden");

      showAlert(
        "⚠️ SECURITY WARNING: Key Changed!",
        `The cryptographic fingerprint for ${recipient} has changed!\nStored: ${stored.fingerprint}\nReceived: ${liveFingerprint}\nThis could indicate a key reset or a potential security risk.`,
        [
          {
            label: "Trust New Key",
            className: "btn btn--primary btn--small",
            onClick: async () => {
              await saveContact({
                username: recipient,
                ecdhJwk: keyData.ecdh_jwk,
                ecdsaJwk: keyData.ecdsa_jwk,
                fingerprint: liveFingerprint,
              });
              isSendingBlocked = false;
              if (sendBtn) sendBtn.disabled = false;
              hideAlert();
              if (contactFingerprintElem) contactFingerprintElem.textContent = liveFingerprint;
              setStatus("New key trusted", "success");
            },
          },
        ]
      );
    }

    currentRecipientKeyData = { ...keyData, fingerprint: liveFingerprint };
  } catch (err) {
    setStatus(`Could not verify contact keys: ${err.message}`, "error");
  }
}

// ---------------------------------------------------------------------------
// Event Listeners
// ---------------------------------------------------------------------------

let recipientDebounceTimer = null;
if (recipientInput) {
  recipientInput.addEventListener("input", () => {
    clearTimeout(recipientDebounceTimer);
    const val = recipientInput.value.trim().toLowerCase();
    recipientDebounceTimer = setTimeout(() => {
      checkContactKeys(val);
    }, 300);
  });
}

socket.on("connect", () => {
  setStatus("Connected to chat server", "success");
});

socket.on("disconnect", () => {
  setStatus("Disconnected from chat server", "error");
});

socket.on("connect_error", (err) => {
  setStatus(`Connection error: ${err.message || "Failed to connect"}`, "error");
});

// Incoming message handler (TEMP-PLAINTEXT until Step 6)
socket.on("message", (payload) => {
  if (!payload || typeof payload !== "object") return;
  const sender = typeof payload.sender === "string" ? payload.sender : "Unknown";
  const text = typeof payload.text === "string" ? payload.text : "";
  appendMessage(sender, text, false);
});

// Form Submission
if (chatForm) {
  chatForm.addEventListener("submit", (e) => {
    e.preventDefault();

    if (isSendingBlocked) {
      setStatus("Sending blocked due to untrusted contact key change", "error");
      return;
    }

    const recipient = recipientInput ? recipientInput.value.trim().toLowerCase() : "";
    const text = messageInput ? messageInput.value : "";

    if (!recipient) {
      setStatus("Please specify a recipient username", "error");
      if (recipientInput) recipientInput.focus();
      return;
    }

    if (!text.trim()) {
      setStatus("Message cannot be empty", "error");
      if (messageInput) messageInput.focus();
      return;
    }

    if (text.length > 2000) {
      setStatus("Message exceeds 2000 characters", "error");
      return;
    }

    if (sendBtn) sendBtn.disabled = true;
    setStatus("Sending...", "info");

    // TEMP-PLAINTEXT: emit unencrypted payload; Step 6 replaces with ciphertext envelope.
    socket.emit(
      "send_message",
      {
        recipient: recipient,
        text: text, // TEMP-PLAINTEXT
      },
      (ack) => {
        if (sendBtn && !isSendingBlocked) sendBtn.disabled = false;

        if (ack && ack.ok) {
          appendMessage(currentUsername, text, true);
          setStatus("Message delivered", "success");
          if (messageInput) {
            messageInput.value = "";
            messageInput.focus();
          }
        } else {
          const errorMsg = ack && ack.error ? ack.error : "Failed to deliver message";
          setStatus(`Error: ${errorMsg}`, "error");
        }
      }
    );
  });
}

// Initialize identity when DOM is ready
initIdentity();
