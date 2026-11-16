# Step 5: Keys, Key Storage and Fingerprints

**Goal:** every user gets two long-term key pairs created in their browser. Public keys are uploaded to the server. Private keys never leave the browser. Contacts' fingerprints are remembered and a change triggers a warning.
**Depends on:** Step 4.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 8, 9, 10.

## Create or modify

`static/js/crypto.js`, `static/js/keystore.js`, `static/js/chat.js`, `templates/chat.html`, `models.py` (key columns already exist), `api.py`, `app.py`.

## Tasks

### Browser

1. `crypto.js` (ES module, Web Crypto only):
   - `generateIdentity()`: create an ECDH P-256 pair (usage `deriveBits`) and an ECDSA P-256 pair (usages `sign`, `verify`), both with `extractable: false`.
   - `exportPublicJwk(key)`: export and **normalise** to exactly `{kty, crv, x, y}`.
   - `exportRaw(key)`: raw uncompressed public point.
   - `fingerprint(ecdhPubKey, ecdsaPubKey)`: SHA-256 of the two raw keys concatenated; return the first 32 hex characters, uppercase, in groups of 4.
2. `keystore.js`: IndexedDB database `e2ee-chat` with stores `identity` (key = username), `contacts` (key = username), `seen` (key = signature hash). CryptoKey objects can be stored directly in IndexedDB. Provide small async helpers: `getIdentity`, `saveIdentity`, `getContact`, `saveContact`.
3. On chat page load (`chat.js`):
   - Call `GET /api/me`. If a local identity exists for this username, use it.
   - If there is no local identity and the server reports `has_keys: false`, generate, store locally, then `POST /api/keys`.
   - If there is no local identity but the server reports `has_keys: true`, show a clear warning: the keys on this browser are gone, old or queued messages cannot be read, and the user may **reset keys** (generate new ones and `PUT /api/keys`). Do not reset automatically.
4. Show the user's own fingerprint in the UI.
5. **TOFU for contacts.** When the user opens a chat with a username, fetch `/api/users/<username>/keys`, compute the fingerprint, and:
   - first time: store it and show it;
   - same as stored: continue;
   - different: block sending and show a prominent warning with the old and new fingerprints and a button "Trust new key" that updates the stored value only after a click.

### Server (`api.py`)

6. `GET /api/me`, `POST /api/keys`, `PUT /api/keys`, `GET /api/users/<username>/keys` exactly as in main section 10, all requiring login and the CSRF header on POST/PUT.
7. **Validate every uploaded JWK:** `kty` is `EC`, `crv` is `P-256`, `x` and `y` are base64url strings that decode to 32 bytes, and **no other member is present**. Reject any JWK containing `d` with 400. Store as a JSON string.
8. `POST /api/keys` returns 409 if the user already has keys. `PUT /api/keys` replaces them.

## Must not do

- Do not set `extractable: true` for private keys.
- Do not put private keys in `localStorage`, cookies, URLs or network requests.
- Do not encrypt messages yet (Step 6).

## Acceptance checks

- [ ] After first login, DevTools Network shows exactly one `POST /api/keys` containing only public JWK fields.
- [ ] DevTools, Application, IndexedDB shows the stored identity; the private keys appear as non-extractable CryptoKey objects.
- [ ] The database `users` row now holds two public JWK strings.
- [ ] A request body that includes a `d` member is rejected with 400.
- [ ] Clearing the site's IndexedDB data and reloading shows the "keys lost" warning and does not reset silently.
- [ ] After a key reset (`PUT /api/keys`), the other user's browser shows the "key changed" warning and blocks until "Trust new key" is clicked.
- [ ] Both users can compare fingerprints on screen.

## Security checklist

- [ ] Searching the whole codebase for `exportKey("pkcs8"` or `"jwk"` on a private key finds nothing.
- [ ] Only the four JWK fields are ever sent or stored.

## Commit

`step 5: identity keys, indexeddb and fingerprints`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_05_keys.md.
Implement ONLY Step 5. First reply with a short plan listing the files you will
create or change. Wait for my approval before editing. After implementing, run the
acceptance checks and report each one as pass or fail. Do not start Step 6.
```
