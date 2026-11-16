# Secure E2EE Messenger: Main Specification

> **For the AI agent:** read this whole file before every task. Then read ONLY the step file you were asked to implement. This file is the single source of truth. If a step file and this file disagree, this file wins; stop and ask.

All files in this set live in one folder (`docs/`). Links below are relative.

---

## 1. Goal

A client-server web messaging app for an information-security course project.

- The server only relays and temporarily stores **encrypted** messages. It never holds a key that can decrypt them.
- The server permanently stores only: usernames, Argon2 password hashes and each user's two **public** keys.
- A message is stored on the server only until the recipient's browser has rendered it. Then it is deleted.
- Optional feature: hide an encrypted message inside an ordinary PNG image (steganography).

---

## 2. How the AI agent must work

1. Read this file, then the one step file you were given. Do not read ahead or implement later steps.
2. Before editing, reply with a short plan: the files you will create or change. Wait for approval.
3. Implement only what the step file lists. If something is unclear or the contract here is missing a detail, **ask**; do not invent.
4. Never change a contract in this file (API, events, formats, crypto parameters) without saying so and getting approval.
5. Never write your own cryptography. Browser crypto uses the Web Crypto API only. Server password hashing uses argon2-cffi only.
6. Do not run destructive shell commands (deleting folders, `git reset --hard`, dropping databases) without asking.
7. Never put real secrets in code, prompts, logs or commits.
8. When finished: run the step's acceptance checks, report each as pass or fail, list files changed, and stop. Do not start the next step.

---

## 3. Step index

Build in this order. Each step must pass its acceptance checks before the next begins, and should end with a Git commit.

| # | File | What it builds | Depends on |
| --- | --- | --- | --- |
| 1 | [STEP_01_setup.md](./STEP_01_setup.md) | Project scaffold, config, app factory | none |
| 2 | [STEP_02_accounts.md](./STEP_02_accounts.md) | Registration, login, logout with Argon2 | 1 |
| 3 | [STEP_03_https.md](./STEP_03_https.md) | HTTPS with mkcert, secure cookies | 2 |
| 4 | [STEP_04_plain_chat.md](./STEP_04_plain_chat.md) | Real-time chat, temporarily unencrypted | 3 |
| 5 | [STEP_05_keys.md](./STEP_05_keys.md) | Key generation, IndexedDB storage, public key directory, fingerprints | 4 |
| 6 | [STEP_06_encryption.md](./STEP_06_encryption.md) | Ephemeral ECDH, HKDF, AES-GCM, ECDSA signatures | 5 |
| 7 | [STEP_07_pending_queue.md](./STEP_07_pending_queue.md) | Store until delivered, acknowledge, delete, expire | 6 |
| 8 | [STEP_08_hardening.md](./STEP_08_hardening.md) | CSP and headers, rate limits, audit log | 7 |
| 9 | [STEP_09_stego_core.md](./STEP_09_stego_core.md) | Standalone steganography library and lab page | 8 |
| 10 | [STEP_10_stego_integration.md](./STEP_10_stego_integration.md) | Stego messages inside the chat | 9 |
| 11 | [STEP_11_tests_and_analysis.md](./STEP_11_tests_and_analysis.md) | Tests, scans, packet and stego analysis | 10 |
| 12 | [STEP_12_report_and_viva.md](./STEP_12_report_and_viva.md) | README, threat model, demo script, viva prep | 11 |

If the team skips steps 9 and 10 (stego), everything else still works.

---

## 4. Assumptions (confirm or change before starting)

- [ ] 1-to-1 chat only (no group chats).
- [ ] Python 3.10 or newer; Flask 3.x; latest stable versions of the libraries below, pinned with `pip freeze` after Step 1.
- [ ] Development on `https://localhost:5000` only (no deployment).
- [ ] SQLite database; no migrations tool (delete and recreate the dev database when the schema changes).
- [ ] Plain JavaScript with ES modules, no frontend framework, no build step.
- [ ] Users find each other by typing an exact username (no public user list).
- [ ] Message history is not kept: once rendered, a message exists only on screen.
- [ ] The instructor allows AI-assisted development (confirm, and check whether it must be disclosed).

---

## 5. Tech stack

| Layer | Choice |
| --- | --- |
| Language | Python 3.10+ |
| Web framework | Flask |
| Real-time | Flask-SocketIO in **threading** mode with `simple-websocket` (no eventlet or gevent) |
| Database | SQLite via Flask-SQLAlchemy (SQLAlchemy ORM only, no raw SQL strings) |
| Password hashing | argon2-cffi (Argon2id) |
| Sessions | Flask-Login with server-signed cookie sessions (no JWT) |
| CSRF | Flask-WTF `CSRFProtect` |
| Headers | Flask-Talisman |
| Rate limiting | Flask-Limiter |
| Config | python-dotenv |
| Frontend | HTML, CSS, vanilla JavaScript, Socket.IO client (vendored file), Web Crypto API, IndexedDB, Canvas API |
| Certificates | mkcert |
| Testing | pytest, Bandit, pip-audit, OWASP ZAP, Wireshark, DB Browser for SQLite |

---

## 6. Architecture

```
Browser A (Alice)                     Flask server                      Browser B (Bob)
- holds private keys                  - users, public keys              - holds private keys
- encrypts + signs                    - pending_messages (ciphertext)   - verifies + decrypts
- optional stego embed                - relays, never decrypts          - optional stego extract
        |  HTTPS / WSS                      |                                  |
        +---------------------------------->|---------------------------------->|
```

Message life cycle: Alice encrypts and signs in her browser, sends it over WSS. The server stores it in `pending_messages` and pushes it to Bob if he is online (or when he next connects). Bob's browser verifies, decrypts and renders it, then sends an acknowledgement. The server deletes the row only on that acknowledgement.

---

## 7. Security rules (non-negotiable)

1. Private keys are generated in the browser, are non-extractable, live only in IndexedDB, and are **never** sent anywhere.
2. The server rejects any uploaded public key JWK that contains a `d` member (a private key).
3. No plaintext message and no key material in the database, logs, error messages or URLs.
4. `crypto.getRandomValues` is the only random source in browser code. Never `Math.random`. Never Python's `random` for anything security related.
5. A fresh random 12-byte IV for every AES-GCM encryption. A fresh ephemeral key pair for every message.
6. Every message is signed. The receiver verifies the signature **before** decrypting or showing anything.
7. All DOM output of user content uses `textContent` (or `createTextNode`). Never `innerHTML`, `outerHTML`, `document.write` or `eval`.
8. No inline scripts and no inline event handlers (the Content-Security-Policy forbids them). All JavaScript lives in `static/js/`.
9. Database access only through the ORM (parameterized). No string-built SQL.
10. Same generic error for wrong username and wrong password.
11. Validate everything again on the server, whatever the browser already checked.
12. `.env`, `certs/`, `instance/` and `logs/` are never committed.

---

## 8. Cryptography specification

| Item | Value |
| --- | --- |
| Curve | P-256 for both ECDH and ECDSA |
| Long-term keys per user | One ECDH pair (`deriveBits`) and one ECDSA pair (`sign`, `verify`). Private keys created with `extractable: false`. |
| Key storage | IndexedDB database `e2ee-chat`, object stores `identity`, `contacts`, `seen` |
| Public key format on the wire and in the DB | JWK containing exactly `kty`, `crv`, `x`, `y` (strip `key_ops`, `ext`, anything else) |
| Raw public key | Uncompressed point (65 bytes), used for the ephemeral key on the wire and for fingerprints |
| Fingerprint | SHA-256 of (raw ECDH public key concatenated with raw ECDSA public key). Show the first 32 hex characters, uppercase, in groups of 4. |
| Ephemeral key | New ECDH P-256 pair per message, usage `deriveBits`, `extractable: false`, discarded right after use. Its raw public key travels with the message. |
| Shared secret | `deriveBits` (256 bits) between the ephemeral private key and the recipient's long-term ECDH public key. The recipient derives the same bits from their long-term private key and the ephemeral public key. |
| KDF | HKDF-SHA256, salt = 32 zero bytes, info = ASCII label, output 256 bits |
| KDF labels | `message-encryption` (AES key), `stego-positions` (stego key). Never reuse one derived value for two purposes. |
| Cipher | AES-256-GCM, 12-byte random IV, 128-bit tag |
| AES-GCM additional data | UTF-8 of `v1\|<kind>\|<sender>\|<recipient>\|<ts>` |
| Signature | ECDSA P-256 with SHA-256, WebCrypto output (64 bytes, r\|\|s) |
| Signed bytes, text | UTF-8 of `JSON.stringify(["v1","text",sender,recipient,ts,eph,iv,ct])` using the base64 strings exactly as sent |
| Signed bytes, stego | UTF-8 of `JSON.stringify(["v1","stego",sender,recipient,ts,eph,sha256_hex_of_png_bytes])` |
| Binary in JSON | Standard base64 |
| Timestamp | `ts` = `Date.now()` in milliseconds from the sender. Receiver rejects if older than 7 days or more than 5 minutes in the future. |
| Replay defence | Receiver stores the SHA-256 of each accepted signature in IndexedDB store `seen` and drops repeats. |
| Receive order | 1) fetch sender keys 2) compare with the stored fingerprint, warn on change 3) verify signature 4) check `ts` 5) check `seen` 6) derive keys and decrypt |
| Key change handling | If a contact's fingerprint differs from the stored one, block and require an explicit "trust the new key" click |

---

## 9. Data model

**users**

| Column | Type | Notes |
| --- | --- | --- |
| id | integer, primary key | |
| username | string(32), unique | stored lowercase; allowed `[a-z0-9_]`, length 3 to 32 |
| password_hash | string | Argon2id hash |
| ecdh_public_jwk | text, nullable | JSON string |
| ecdsa_public_jwk | text, nullable | JSON string |
| created_at | datetime | |

**pending_messages**

| Column | Type | Notes |
| --- | --- | --- |
| id | integer, primary key | |
| sender_id | foreign key to users | |
| recipient_id | foreign key to users | indexed |
| kind | string | `text` or `stego` |
| ciphertext | text | `ct` (base64) for text, `img` (base64 PNG) for stego |
| iv | text, nullable | text messages only |
| ephemeral_public_key | text | base64 raw point |
| signature | text | base64 |
| client_ts | bigint | sender's `ts` |
| created_at | datetime | server time, used for expiry |

**login_attempts** (added in Step 8): id, username, ip, success, created_at.

No table ever holds plaintext or private keys.

---

## 10. HTTP API contract

All state-changing requests (POST, PUT) need the CSRF token in the `X-CSRFToken` header (read from `<meta name="csrf-token">`), or the hidden form field for HTML forms. Errors are JSON `{"error": "<short message>"}` with the right status code.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET, POST | `/register` | no | Registration form |
| GET, POST | `/login` | no | Login form |
| POST | `/logout` | yes | End session |
| GET | `/chat` | yes | Chat page |
| GET | `/api/me` | yes | `{username, has_keys}` |
| POST | `/api/keys` | yes | Upload first public keys `{ecdh_jwk, ecdsa_jwk}`. 409 if keys already exist. |
| PUT | `/api/keys` | yes | Replace keys (explicit key reset). Audit-logged. |
| GET | `/api/users/<username>/keys` | yes | `{username, ecdh_jwk, ecdsa_jwk}`; 404 if unknown or no keys |

---

## 11. Socket.IO contract

Authentication uses the Flask session cookie. Unauthenticated connections are refused. Allowed origins are the exact HTTPS origins of the app.

| Event | Direction | Payload | Behaviour |
| --- | --- | --- | --- |
| `connect` | client to server | none | Refuse if not logged in. Join room `user:<id>`. Push queued messages (oldest first, at most 200). |
| `send_message` | client to server | envelope (section 12) | Validate, store in `pending_messages`, push to the recipient's room. Ack: `{ok:true, id}` or `{ok:false, error}`. |
| `message` | server to client | `{id, ...envelope}` | Delivered to the recipient. |
| `ack_message` | client to server | `{id}` | Delete the row only if `recipient_id` equals the session user. Ack: `{ok:true}`. |

The server never logs payload contents.

---

## 12. Message envelope formats

Text:

```json
{"v":1,"kind":"text","sender":"alice","recipient":"bob","ts":1731600000000,
 "eph":"<base64 raw P-256 public key>","iv":"<base64 12 bytes>","ct":"<base64>","sig":"<base64>"}
```

Stego:

```json
{"v":1,"kind":"stego","sender":"alice","recipient":"bob","ts":1731600000000,
 "eph":"<base64 raw P-256 public key>","img":"<base64 PNG bytes>","sig":"<base64>"}
```

Server-side checks: `sender` equals the session user; `recipient` exists; `v` is 1; `kind` is known; all fields present with correct types; valid base64; size limits from section 14.

---

## 13. Folder layout

```
secure-chat/
├── app.py                  # create_app(), socketio.run()
├── extensions.py           # db, login_manager, csrf, limiter, socketio
├── config.py               # settings loaded from .env
├── models.py               # User, PendingMessage, LoginAttempt
├── auth.py                 # register/login/logout blueprint
├── api.py                  # /api/* blueprint
├── events.py               # Socket.IO handlers
├── cleanup.py              # expiry of old pending messages
├── requirements.txt
├── .env  .env.example  .gitignore
├── certs/                  # mkcert files (never commit)
├── instance/               # SQLite file (never commit)
├── logs/                   # audit log (never commit)
├── templates/              # base.html login.html register.html chat.html stego_lab.html
├── static/
│   ├── css/style.css
│   └── js/
│       ├── crypto.js       # keys, ECDH, HKDF, AES-GCM, ECDSA
│       ├── keystore.js     # IndexedDB
│       ├── chat.js         # UI + Socket.IO client
│       ├── stego.js        # steganography
│       └── vendor/socket.io.min.js
├── tools/stego_analysis.py
├── tests/
└── docs/                   # this specification set
```

---

## 14. Configuration (`.env`)

Never commit `.env`. Commit `.env.example` with names and no real values.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECRET_KEY` | none, required | Flask session signing key (long random string) |
| `DATABASE_URL` | `sqlite:///chat.db` | Stored under `instance/` |
| `SSL_CERT`, `SSL_KEY` | `certs/localhost.pem`, `certs/localhost-key.pem` | mkcert files |
| `MESSAGE_TTL_DAYS` | `7` | Undelivered messages older than this are deleted |
| `MAX_TEXT_BYTES` | `16384` | Max size of a text envelope |
| `MAX_STEGO_BYTES` | `3145728` | Max size of the decoded PNG in a stego envelope |
| `MAX_PENDING_PER_PAIR` | `100` | Max queued messages from one sender to one recipient |
| `SESSION_MINUTES` | `30` | Session lifetime |
| `STEGO_LAB` | `0` | Set `1` to enable the `/stego-lab` page |

---

## 15. Coding conventions

- Python: PEP 8, small functions, type hints where easy, docstring on each route and event.
- Comment every security decision with a `# SECURITY:` (Python) or `// SECURITY:` (JavaScript) line saying what it prevents.
- Temporary code that a later step removes is marked `TEMP-PLAINTEXT` so it is easy to find.
- Commit messages: `step N: short description`.
- Do not add libraries beyond section 5 without asking.

---

## 16. Definition of done (every step)

1. All acceptance checks in the step file pass.
2. No new secrets, plaintext message handling or key material outside the rules in section 7.
3. The app starts cleanly and earlier steps still work.
4. Changes committed with a clear message.

---

## 17. Glossary

- **E2EE:** end-to-end encryption; only the two users hold the keys.
- **Ephemeral key:** a short-lived key pair made for one message and then discarded.
- **ECDH:** key agreement; two parties derive the same secret from each other's public keys.
- **HKDF:** turns a shared secret into one or more independent keys using labels.
- **AES-GCM:** encryption that also detects tampering.
- **ECDSA:** digital signature that proves who sent a message.
- **TOFU:** trust on first use; remember a contact's key fingerprint and warn if it changes.
- **LSB:** least significant bit, the lowest bit of a colour value, used to hide data in images.
