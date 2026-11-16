# Step 4: Real-Time Chat (Temporarily Unencrypted)

**Goal:** two logged-in users can exchange live messages over WSS. This step proves the real-time plumbing works before any cryptography is added. Everything plaintext here is temporary.
**Depends on:** Step 3.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 10, 11, 15.

## Create or modify

`events.py`, `app.py`, `extensions.py`, `templates/chat.html`, `static/js/chat.js`, `static/js/vendor/socket.io.min.js`, `static/css/style.css`.

## Tasks

1. **Vendor the client.** Download `socket.io.min.js` (Socket.IO client 4.x, compatible with the installed python-socketio 5.x) from the official project and save it to `static/js/vendor/`. Serve it locally so the Content-Security-Policy in Step 8 can stay `script-src 'self'`. No CDN links.
2. `extensions.py`: create `SocketIO(async_mode="threading", cors_allowed_origins=["https://localhost:5000", "https://127.0.0.1:5000"], max_http_buffer_size=5_000_000)`.
3. `events.py` handlers:
   - `connect`: refuse (return `False`) unless `current_user.is_authenticated`. Join room `user:<id>`.
   - `send_message` with payload `{recipient, text}`: validate that the recipient exists and the text is a non-empty string under 2000 characters. Emit `message` `{sender, text}` to the recipient's room. Return an ack `{ok:true}` or `{ok:false, error}`.
   - Mark the plaintext fields with `# TEMP-PLAINTEXT` comments. Step 6 removes them.
4. `chat.html` and `chat.js`: an input for the recipient's exact username, a message list, a text box and a send button. The client connects with `io({transports:["websocket"]})` so the WebSocket frames are easy to inspect.
5. Render every message with `textContent`. Never `innerHTML`.
6. Show "sent" or an error based on the ack. Show incoming messages as they arrive.
7. Nothing is stored in the database in this step. Messages to offline users are simply refused with `{ok:false, error:"recipient offline"}` for now (Step 7 replaces this).

## Must not do

- Do not store messages.
- Do not use inline scripts, inline handlers or a CDN.
- Do not broadcast to all users; only to the recipient's room.

## Acceptance checks

- [ ] Two browsers (normal window plus a private window) logged in as two users can chat live.
- [ ] DevTools, Network tab, WS filter: frames travel over `wss://localhost:5000`.
- [ ] Opening the Socket.IO connection without being logged in is refused.
- [ ] Sending `<script>alert(1)</script>` as a message shows as harmless text.
- [ ] A message to a non-existent user returns an error ack.
- [ ] A user cannot send to a recipient's room by guessing ids (the server resolves the username itself).

## Security checklist

- [ ] The server uses the session user as the sender; it never trusts a `sender` field from the client.
- [ ] No message content is logged.

## Commit

`step 4: plain real-time chat`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_04_plain_chat.md.
I have placed socket.io.min.js in static/js/vendor/.
Implement ONLY Step 4. First reply with a short plan listing the files you will
create or change. Wait for my approval before editing. After implementing, run the
acceptance checks and report each one as pass or fail. Do not start Step 5.
```
