# Step 6 implementation and acceptance checks

Validated on 17 November 2026. All seven Step 6 acceptance checks pass.

## Step 6 acceptance

| Check from STEP_06_encryption.md | Result | Evidence |
| --- | --- | --- |
| WebSocket frames contain only the encrypted envelope, with no message plaintext | PASS | Captured actual WSS frames in Chrome; checked envelope fields and absence of test plaintext. Server rejects additional plaintext fields. |
| Two browsers exchange readable messages | PASS | Separate Chrome browser contexts, different accounts, real Flask-SocketIO relay, Web Crypto and IndexedDB. Both directions also pass after explicit trust of a reset key. |
| selfTest normal case and tamper cases pass | PASS | All nine cases pass using Chrome Web Crypto and the stored local identity. Signature checking precedes decryption. |
| Identical captured envelope is dropped by seen | PASS | Replayed a captured envelope through the real server; browser reported replay and rendered no duplicate. |
| Eight-day-old or ten-minute-future timestamps rejected | PASS | Created genuinely signed envelopes with these timestamps and delivered them over WSS; receiver rejected both before rendering. |
| Server contains no decryption call or plaintext message field | PASS | Source inspection and regression test rejecting plaintext fields. |
| Two messages have different eph and IV values | PASS | Compared successive real browser sends. |

Security checklist: signature verification precedes decryption; sending and receiving use the specified AAD; no `Math.random` remains anywhere under `static/js/`, including the locally adjusted vendor file. The P-256, HKDF-SHA256, AES-256-GCM, ECDSA-SHA256, IV/tag sizes, signature bytes and text-envelope contracts are unchanged.

## Fixes and prerequisite regressions

- Fixed account-scoped contact storage, with an atomic IndexedDB version-2 migration preserving identities, prior contact fingerprints and replay records. Ownerless legacy records require explicit review.
- Bound encryption keys to the selected username, invalidated stale selections, ignored outdated lookup results, and refreshed contact keys on every send. Immediate recipient switching passes the browser regression check.
- Blocked both sending and receiving after a contact key change until explicit trust. The trust button refetches the key so an old warning cannot approve a later replacement; concurrent send/receive warnings for the same fingerprint are handled.
- Saved private identities durably before uploading public keys. Browser-injected storage aborts prevent uploads and connection; failed uploads preserve the identity, and reload retries the same keys.
- Deferred socket connection until identity setup succeeds. Lost or mismatched local keys produce an explicit reset warning without a silent reset or connection.
- Enforced the complete text-envelope size limit, strict integer version/timestamp types, canonical base64, ephemeral-point prefix/length, 12-byte IV, 64-byte signature and minimum AES-GCM tag length.
- Enforced strict base64url public-key coordinates while retaining exact four-field JWK validation and private-key rejection.
- Returned JSON API errors for authentication, CSRF and HTTP errors, while retaining the logged-out chat redirect.
- Disconnected existing chat sockets on account logout and synchronized connection tracking with relays.
- Registered event handlers on each factory-created Socket.IO server, allowing repeatable isolated regression tests.
- Corrected the misleading forward-secrecy comment and made sender status accurately report server relay rather than recipient rendering.

## Verification

| Command/check | Result |
| --- | --- |
| `venv/Scripts/python.exe -m pytest -q -p no:cacheprovider` | 38 passed |
| `node tests/browser_step6.mjs` | 30 passed, 0 failed |
| `venv/Scripts/python.exe -m bandit app.py api.py auth.py config.py events.py extensions.py models.py -q` | Passed, no reported issues |
| `venv/Scripts/python.exe -m pip check` | Passed, no broken requirements |
| `node --check` on chat.js, crypto.js, keystore.js, vendor/socket.io.min.js and tests/browser_step6.mjs | Passed |
| `git diff --check` | Passed |
| Search client source for temporary plaintext paths, unsafe DOM APIs, private-key export formats and non-cryptographic randomness | Passed |

The server suite checks account/cookie prerequisites, API key lifecycle, private/malformed JWK rejection, authenticated connections, origin rejection, recipient-only relay, logout revocation, malformed envelopes and the exact size boundary.

The browser suite verifies actual trusted HTTPS/WSS, readable two-account chat, public-key upload order, nonextractable IndexedDB keys, crypto self-tests, replay/timestamp/tamper rejection, key-loss/reset/trust behavior, recipient changes, version-1 migration, storage/upload failure recovery, and live logout. It uses an in-memory database and mock audit writer. It runs on a separate exact localhost origin at port 5443 so an existing listener on 5000 can remain undisturbed; no certificate-verification bypass is used.

The existing mkcert CA was installed in the computer's trust store after explicit user authorization. Chrome then loaded the isolated application without the previous certificate error. Existing application account data, private identity data and certificates were not replaced.

## Files changed

Application: `api.py`, `app.py`, `auth.py`, `events.py`, `static/js/chat.js`, `static/js/crypto.js`, `static/js/keystore.js`, and `static/js/vendor/socket.io.min.js`.

Validation/documentation: `tests/test_step6.py`, `tests/browser_step6.mjs`, `README.md`, this results file, and a follow-up note in `REVIEW_STEPS_01_06.md`.

Step 7 pending storage, acknowledgments/deletion and expiry remain outside this change. Offline recipients continue to return an error. Later hardening and steganography steps were not implemented.
