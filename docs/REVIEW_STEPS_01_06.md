# Review of implementation through Step 6

> Follow-up, 17 November 2026: the findings below describe the original review snapshot. They have since been addressed; see [Step 6 implementation and acceptance results](STEP_06_encryption.checks.md) for the current status and rerun commands.

Reviewed on 16 November 2026 against `PROJECT_MAIN.md` and `STEP_01_setup.md` through `STEP_06_encryption.md`.

**Verdict: REQUEST CHANGES.** The main functionality through Step 6 exists, and the specified cryptographic operations work. Steps 5 and 6 cannot be signed off because contact trust is broken and recipient selection can use the wrong encryption key. The Step 3 trusted-certificate check also fails in this environment.

All authored Python, JavaScript, templates, CSS, configuration examples, and README were read. The vendored Socket.IO client was checked for presence and version (4.8.1); its upstream minified implementation was not independently audited. Existing source modifications were reviewed as the current implementation and left untouched. Real `.env` secrets, private certificate contents, and application account data were not printed. Tests used generated accounts and an in-memory database; the existing certificate/key were used only to start the isolated local HTTPS listener.

## Findings, in priority order

### 1. High: stored contact trust is never retrieved

Locations: `static/js/keystore.js:38`, `:133`, `:162`, `:168`; callers in `static/js/chat.js:292` and `:430`.

The `contacts` object store has `keyPath: "username"`. `saveContact()` stores a record whose primary key is therefore `bob`, while `getContact("bob", "alice")` looks up `alice:bob`. The record's separate `key` property is not its IndexedDB primary key. Every lookup misses, so both sending and receiving treat previously known contacts as first contacts and overwrite their remembered fingerprints. Separate accounts also overwrite the same contact record.

Reproduced with actual Chrome IndexedDB and the actual client modules: a saved contact could not be retrieved; replacing Bob's keys produced no trust warning or sending block; a valid incoming message signed with the replacement key was rendered without a trust click.

Required fix: use the same account-scoped primary key for reads and writes, with a versioned IndexedDB migration for existing databases. Preserve or explicitly reconcile existing trust records rather than silently discarding them. Recheck both send and receive paths after the migration.

### 2. High: changing recipients can encrypt using the previous contact's key

Locations: `static/js/chat.js:364`, `:352`, `:555`, `:573`.

Changing the recipient leaves `currentRecipientKeyData` available until the debounced asynchronous lookup completes. Submission reads the new input value but encrypts using the existing cached key. There is no check that `currentRecipientKeyData.username` matches the selected recipient. Failed requests also leave stale state, and overlapping requests can finish out of order.

Reproduced in Chrome: select Bob, change the input to Alice, and immediately submit. The resulting signed envelope names Alice as recipient but decrypts using Bob's private key. The server can report success even though the named recipient cannot read it.

Required fix: invalidate cached recipient keys immediately on input changes, block submission while verification is pending, ignore results for obsolete requests, and bind the validated username and key together immediately before encryption.

### 3. Medium: logout does not revoke an existing Socket.IO connection

Locations: `auth.py:203`; `events.py:112`, `:147`; connection tracking at `events.py:120`.

Authentication is checked against the socket's session context, but the HTTP logout handler does not disconnect or revoke the sockets authenticated by that session. In the Flask-SocketIO test, after successful HTTP logout, the already connected socket still sent a message and received `{ok: true}`. It also remains in its recipient room until disconnected.

Required fix: revoke/disconnect the sockets associated with the logged-out session and ensure subsequent events cannot use its former authenticated state. Verify sending and receiving after logout, including another open tab.

### 4. Medium: MAX_TEXT_BYTES limits ciphertext rather than the complete envelope

Location: `events.py:92` through `:100`.

The main specification defines `MAX_TEXT_BYTES` as the maximum size of a text envelope. The implementation checks only decoded `ct`. With the default 16,384-byte limit, a serialized envelope of 22,166 bytes was accepted. A separate envelope with a 50,000-byte decoded signature and small ciphertext was also accepted. The transport's 5,000,000-byte buffer does not implement the documented text-envelope limit.

Required fix: enforce the complete serialized envelope byte limit and sensible per-field limits before decoding large fields.

### 5. Medium: malformed envelope types and cryptographic lengths are relayed

Locations: `events.py:71`, `:92` through `:97`.

The version equality check accepts Python `True` and `1.0` as version 1. A one-byte decoded signature and one-byte ciphertext also pass validation. The signature must be 64 bytes under the specified Web Crypto format, and AES-GCM ciphertext must include its 16-byte tag. The ephemeral key length is checked, but its uncompressed-point prefix is not.

Reproduced through the actual server event handler. The browser rejects malformed messages later, but the server-side validation contract is not met.

Required fix: check version type as well as value; validate signature length, minimum authenticated ciphertext length, and public-point encoding. Keep receiver verification before decryption.

### 6. Medium: public JWK coordinates use permissive base64 decoding

Location: `api.py:98` through `:104`.

`urlsafe_b64decode()` is used without strict alphabet validation. The validator accepts coordinates containing invalid characters, such as `!!!!` prefixed to a valid 43-character coordinate. It also accepts the standard-base64 `+` character, which is outside the base64url alphabet. These inputs can still decode to 32 bytes and be stored, despite the required base64url validation.

Required fix: validate the base64url alphabet/padding and decode strictly, returning 400 for malformed coordinates. Retain the exact four-field check and rejection of `d`, which already work.

### 7. Medium: API authentication and CSRF failures violate the JSON error contract

Locations: `app.py:38`, `:80`; `api.py:115`, `:126`, `:157`, `:182`.

An unauthenticated `GET /api/me` returns a 302 HTML login redirect. A key upload without a CSRF token returns a 400 HTML error page. The main HTTP contract requires API errors to use `{ "error": "..." }` with an appropriate status. The browser's fetch code expects JSON and otherwise receives misleading parse or initialization failures.

Required fix: return JSON authentication errors for `/api/*` while preserving the expected login redirect for `/chat`, and add JSON handling for API CSRF failures.

### 8. Medium: initial public keys are uploaded before the private identity is persisted

Location: `static/js/chat.js:186` through `:204`.

Step 5 specifies generate, store locally, then upload public keys. The current order commits the public keys on the server first. If IndexedDB storage then fails, or the page closes between these operations, the server holds keys whose private halves have been lost. A subsequent visit requires a reset, and messages encrypted to the uploaded keys cannot be recovered.

This finding follows from the source ordering; storage-failure injection was not performed.

Required fix: durably store the private identity before publishing its public keys, and implement retry/reconciliation for a failed or ambiguous upload. Storage helpers should resolve writes on transaction completion and handle transaction aborts, rather than treating request success alone as a committed write.

### 9. Medium: incoming messages can arrive before identity initialization finishes

Locations: `static/js/chat.js:52`, `:399`, `:508`, `:617`.

The socket connects before `initIdentity()` finishes. The server then considers the user online, but any message processed while `localIdentity` is null is rejected as "local identity not ready" and discarded. Step 6 has no pending-message retry. A sender can receive a successful relay acknowledgment while the recipient loses the message during startup.

This finding follows from the initialization and receive ordering; the timing failure was not injected in the browser fixture.

Required fix: initialize identity before connecting, or gate incoming processing on an identity-ready promise while retaining messages until initialization completes.

## HTTPS acceptance blocker

The isolated application started successfully with the configured certificate and key. A TLS request verified successfully when explicitly supplied the local mkcert root CA. Plain HTTP did not serve the application.

However, a fresh headless Chrome profile navigating to `https://localhost:5000/register` failed with `net::ERR_CERT_AUTHORITY_INVALID` and displayed the browser privacy warning. The application therefore does not currently pass the Step 3 "padlock and no warning" check in the browser used for review. Verify installation of the local mkcert CA for the intended user/browser and rerun the normal HTTPS/WSS browser checks. Certificate verification was not disabled, and no trust settings or certificates were changed during review.

## Acceptance-check results

`PASS` means directly tested or verified in source where appropriate. `PARTIAL` means components passed but the exact complete acceptance scenario was not established. `NOT RUN` means the check is still outstanding. Historical HTTP and plaintext behavior in Steps 1 and 4 is superseded by Steps 3 and 6.

### Step 1: setup

| Acceptance check | Result | Evidence |
| --- | --- | --- |
| Install requirements in a fresh virtual environment | NOT RUN | Existing environment passes `pip check`; fresh installation was not attempted. |
| Application starts and root returns 200 | PASS | Isolated in-memory app started over HTTPS; root returned 200 with the test client. The original HTTP requirement is superseded by Step 3. |
| Missing SECRET_KEY fails helpfully | PASS | Configuration validation raised the expected clear error. |
| Local secrets, virtualenv, certificates, and runtime DB are ignored | PASS | `git check-ignore` confirmed the relevant paths; tracked file list contains no `.env`, certificate, or runtime DB. |
| Example environment has no real secret | PASS | Placeholder secret and documented configuration names only. |

Additional security checks: debug disabled in code; all authored Python files parse; dependencies are pinned; no real hard-coded application secret found in reviewed source.

### Step 2: accounts

| Acceptance check | Result | Evidence |
| --- | --- | --- |
| Registration stores an Argon2id hash | PASS | Registered test users in an in-memory database; hashes start with `$argon2id$`. |
| Wrong password and unknown username have identical error text | PASS | Both return the same generic message. Dummy verification and rehash handling are present. |
| Logged-out chat redirects; logged-in chat works | PASS | HTTP test-client checks. |
| Logout requires POST and valid CSRF | PASS | GET returned 405, missing token returned 400, valid POST logged out HTTP session. Existing socket revocation is a separate finding above. |
| Alice and alice cannot both register | PASS | Case-insensitive duplicate rejected; stored names are lowercase. |
| Five-character password rejected | PASS | Registration form rejected it. |
| Session cookie HttpOnly and SameSite=Lax | PASS | Verified the actual session cookie. It also has Secure and an expiry. |

Cookie test correction: Flask also emits an expired remember-cookie deletion header. An initial probe inspected the first `Set-Cookie` header, incorrectly flagging missing flags. Inspecting all headers confirmed the session cookie is correct; there is no cookie-flag finding.

### Step 3: HTTPS

| Acceptance check | Result | Evidence |
| --- | --- | --- |
| HTTPS login has a trusted certificate and no warning | FAIL | Chrome reported `ERR_CERT_AUTHORITY_INVALID`. |
| Plain HTTP does not serve the app | PASS | Request to the isolated TLS listener did not return the application over HTTP. |
| Session cookie Secure flag | PASS | Correct actual session-cookie header and configuration. |
| Missing certificate fails helpfully | PASS | Configuration validation names missing certificate and mkcert commands. |
| Certificates ignored by Git | PASS | `git check-ignore` and tracked-file inspection. |

### Step 4: real-time transport, as retained after encryption

| Acceptance check | Result | Evidence |
| --- | --- | --- |
| Two logged-in browsers exchange live messages | PARTIAL | Authenticated server clients relay successfully; actual browser source encrypts/decrypts/renders in a fixture. Full two-browser application exchange remains outstanding because Chrome does not trust the certificate. |
| DevTools frames use WSS | NOT RUN | Client forces WebSocket transport on current origin and app starts with TLS; actual browser WSS frames were not established. |
| Unauthenticated Socket.IO refused | PASS | Socket.IO test client could not connect. |
| Script-like message displays as harmless text | PASS | Actual Chrome DOM rendered the literal script text with no child elements. |
| Nonexistent recipient returns error acknowledgment | PASS | Actual server event handler rejects unknown recipient. |
| Recipient room cannot be selected by guessed id | PASS | Server resolves the username; envelope allows no extra room/id fields. Relay went only to Bob's room. |

Additional checks: disallowed cross-origin handshake returned 400; transport is threading mode; vendored Socket.IO is served locally; offline recipients are rejected as required before Step 7.

### Step 5: identity keys and fingerprints

| Acceptance check | Result | Evidence |
| --- | --- | --- |
| First initialization sends one public-only POST | PASS | Browser fixture captured exactly one POST containing only the four public JWK fields; server key-upload behavior tested separately. |
| Identity stored as nonextractable CryptoKeys in IndexedDB | PASS | Checked actual Chrome IndexedDB records and both private-key extractable flags. |
| User row stores two public JWK strings | PASS | In-memory ORM database inspection. |
| Uploaded private `d` member rejected with 400 | PASS | API test with valid CSRF. Extra members also rejected. |
| Lost local identity warns without automatic reset | PASS | Removed the fixture identity, reloaded, and observed the missing-keys warning with no extra upload/reset request. |
| Key reset triggers key-change block until explicit trust | FAIL | Stored contact cannot be retrieved; replacement keys were silently accepted in both directions. PUT replacement endpoint itself passes. |
| Both users can compare on-screen fingerprints | PARTIAL | Own and contact fingerprint display/computation verified; full two-user application demo outstanding. |

Additional checks: public exports explicitly reject private keys; no private-key export or localStorage path found. Fingerprint output matches the specified formatting. Strict base64url validation and durable storage ordering still need correction.

### Step 6: encryption and signatures

| Acceptance check | Result | Evidence |
| --- | --- | --- |
| WebSocket frames contain only encrypted envelope fields | PARTIAL | Browser UI produces only the specified signed encrypted envelope; server relays it unchanged and rejects extra plaintext fields. Actual browser WSS capture outstanding. |
| Two browsers exchange readable encrypted messages | PARTIAL | Independent identities encrypt/decrypt correctly; browser UI receive path works in fixture and server relay works separately. Full application integration check outstanding. |
| selfTest normal and tamper cases pass | PASS | All nine selfTest cases passed in both Node Web Crypto and actual Chrome Web Crypto. |
| Identical captured envelope dropped by seen store | PASS | Actual Chrome receive handler and actual IndexedDB rejected a duplicate and did not add another message. |
| Eight-day-old / ten-minute-future messages rejected | PASS | Genuinely signed envelopes with those timestamps were rejected by the actual browser receive UI before rendering. |
| Server has no decrypt call or plaintext message field | PASS | Server source inspection and rejection of plaintext payload fields. |
| Two messages have different ephemeral keys and IVs | PASS | Confirmed in direct crypto tests and actual browser UI sends. |

Additional checks: P-256, 256-bit ECDH, HKDF-SHA256 with 32 zero salt bytes and `message-encryption`, AES-256-GCM with 12-byte IV/128-bit tag, specified AAD, and ECDSA-SHA256 signing bytes match the specification. Signature verification precedes timestamp/replay checks and decryption. DOM rendering uses textContent. No `TEMP-PLAINTEXT` path or `Math.random` appears in authored client code. Complete envelope validation and startup readiness remain open findings.

## Validation performed and limits

- `venv/Scripts/python.exe -m pip check`: PASS, no broken requirements.
- `venv/Scripts/python.exe -m bandit app.py api.py auth.py config.py events.py extensions.py models.py -f json`: PASS, seven files scanned, no reported issues. Bandit did not detect the logic defects above.
- Python AST parsing for all authored server modules: PASS.
- `node --check` for chat.js, crypto.js, and keystore.js: PASS.
- `venv/Scripts/python.exe -m pytest -q -p no:cacheprovider`: no tests collected. There is currently no repository test suite; the dedicated testing step is Step 11.
- Ad hoc HTTP and Socket.IO checks used an in-memory database, generated test-only accounts/secrets, valid CSRF tokens, and a mocked audit writer. Existing account data and audit logs were not changed.
- Node Web Crypto exercised all nine selfTest cases plus independent sender/recipient encryption, fresh ephemeral keys and IVs, fingerprints, normalized public JWKs, and nonextractable private keys.
- A separate Chrome fixture ran the actual source modules against actual Web Crypto, IndexedDB, and DOM. It reported 12 passing and 5 failing assertions. Its directory and socket were test doubles, and its loopback HTTP origin was a separate fixture, not a changed application listener. These are client-logic checks, not evidence of working application HTTPS/WSS integration.
- The actual isolated HTTPS application failed the browser trust check without bypassing certificate verification. Fresh dependency installation, pip-audit network queries, Wireshark, ZAP, and a full normal/private-window application demo were not run.

## Scope and completion notes

Pending-message persistence, acknowledgments/deletion, expiry, CSP/rate limiting, and steganography belong to later steps and are not counted as missing Step 1-6 implementation. Step 4 plaintext behavior is correctly removed by Step 6.

The latest commit is the Step 5 commit (`294706f`); Step 6 changes remain in the working tree. The documented per-step commit requirement is therefore not yet satisfied for Step 6. Original modified files were api.py, events.py, static/js/chat.js, static/js/crypto.js, and static/js/keystore.js; `.sixth/` was already untracked.

One explanatory comment should also be corrected: `static/js/crypto.js:360` claims an ephemeral sender key prevents retrospective exposure from a compromised long-term key. This construction does not protect recorded envelopes against later compromise of the recipient's long-term ECDH private key, which is sufficient to decrypt them using the transmitted ephemeral public key. This is a documentation correction to the current design, not a request to change the specified cryptographic protocol.

Application source was not modified by this review. Only this review document was added.
