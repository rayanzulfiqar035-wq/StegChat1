/**
 * Real-time chat client (Step 4: plain transport verification).
 *
 * All plaintext messaging here is temporary and marked TEMP-PLAINTEXT.
 *
 * SECURITY:
 * - DOM manipulation strictly uses textContent / createTextNode (Rule 7).
 * - Zero innerHTML, outerHTML, document.write, or eval.
 * - Transport is forced to WebSocket only (transports: ["websocket"]) over TLS.
 */

// Connect strictly using WebSockets over the current secure origin (WSS).
const socket = io({
  transports: ["websocket"],
});

const currentUsernameElem = document.getElementById("current-username");
const currentUsername = currentUsernameElem ? currentUsernameElem.textContent.trim().toLowerCase() : "";

const messagesList = document.getElementById("messages-list");
const chatStatus = document.getElementById("chat-status");
const chatForm = document.getElementById("chat-form");
const recipientInput = document.getElementById("recipient-input");
const messageInput = document.getElementById("message-input");
const sendBtn = document.getElementById("send-btn");

/**
 * Display a temporary status or error notification.
 * @param {string} text
 * @param {"info" | "error" | "success"} type
 */
function setStatus(text, type = "info") {
  if (!chatStatus) return;
  chatStatus.textContent = text; // SECURITY: textContent only
  chatStatus.className = `chat-status chat-status--${type}`;
}

/**
 * Append a message bubble to the chat window safely using DOM textContent.
 * @param {string} sender
 * @param {string} text
 * @param {boolean} isSelf
 */
function appendMessage(sender, text, isSelf) {
  if (!messagesList) return;

  const item = document.createElement("div");
  item.className = `message-item ${isSelf ? "message-item--outgoing" : "message-item--incoming"}`;

  const header = document.createElement("div");
  header.className = "message-header";

  const senderSpan = document.createElement("span");
  senderSpan.className = "message-sender";
  // SECURITY: Rule 7 - textContent prevents XSS
  senderSpan.textContent = isSelf ? "You" : sender;
  header.appendChild(senderSpan);

  const body = document.createElement("div");
  body.className = "message-body";
  // SECURITY: Rule 7 - textContent ensures script tags and HTML render as harmless text
  body.textContent = text;

  item.appendChild(header);
  item.appendChild(body);
  messagesList.appendChild(item);

  // Auto-scroll to latest message
  messagesList.scrollTop = messagesList.scrollHeight;
}

// ---------------------------------------------------------------------------
// Socket.IO Events
// ---------------------------------------------------------------------------

socket.on("connect", () => {
  setStatus("Connected to chat server", "success");
});

socket.on("disconnect", () => {
  setStatus("Disconnected from chat server", "error");
});

socket.on("connect_error", (err) => {
  setStatus(`Connection error: ${err.message || "Failed to connect"}`, "error");
});

// Incoming message handler
// TEMP-PLAINTEXT: unencrypted message; Step 6 replaces this with envelope verification & decryption.
socket.on("message", (payload) => {
  if (!payload || typeof payload !== "object") return;
  const sender = typeof payload.sender === "string" ? payload.sender : "Unknown";
  const text = typeof payload.text === "string" ? payload.text : "";
  appendMessage(sender, text, false);
});

// ---------------------------------------------------------------------------
// Form Submission
// ---------------------------------------------------------------------------

if (chatForm) {
  chatForm.addEventListener("submit", (e) => {
    e.preventDefault();

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
        if (sendBtn) sendBtn.disabled = false;

        if (ack && ack.ok) {
          // Render outgoing message in chat thread
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
