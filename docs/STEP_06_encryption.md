# Step 6: End-to-End Encryption and Signatures

**Goal:** messages are encrypted with a fresh ephemeral key per message, signed by the sender, and verified and decrypted only in the recipient's browser. The server sees only ciphertext.
**Depends on:** Step 5.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 8, 11, 12. Follow section 8 exactly.

## Create or modify

`static/js/crypto.js`, `static/js/chat.js`, `events.py`, `static/js/keystore.js` (the `seen` store).

## Tasks

### Sending (`crypto.js` plus `chat.js`)

1. Create a new ephemeral ECDH P-256 pair (`extractable: false`, usage `deriveBits`).
2. `deriveBits` (256) between the ephemeral private key and the recipient's long-term ECDH public key (imported from the JWK).
3. Import the shared bits as an HKDF key and derive the AES-256-GCM key with salt = 32 zero bytes and info = `message-encryption`.
4. Create a random 12-byte IV with `crypto.getRandomValues`. Encrypt the text (UTF-8) with AES-GCM using additional data `v1|text|<sender>|<recipient>|<ts>`.
5. Sign `JSON.stringify(["v1","text",sender,recipient,ts,eph,iv,ct])` with the sender's ECDSA private key (base64 strings exactly as they will be sent).
6. Send the envelope (main section 12, `kind: "text"`) via `send_message`. Discard the ephemeral private key.

### Receiving

7. On `message`, in this order: fetch and TOFU-check the sender's keys (Step 5), verify the signature, check `ts` (not older than 7 days, not more than 5 minutes ahead), check the `seen` store for the signature hash, derive the same AES key (own long-term ECDH private key plus the ephemeral public key), decrypt with the same additional data, render with `textContent`.
8. Only after a successful render, record the signature hash in `seen`. (The acknowledgement to the server is added in Step 7; for now just record it.)
9. If any check fails, show "message rejected" with a short reason in the UI, never the content, and do not render anything from the payload.

### Server (`events.py`)

10. Replace the `TEMP-PLAINTEXT` handler. Validate the envelope structure, sizes (`MAX_TEXT_BYTES`), base64 validity, `sender` equals the session user, `recipient` exists, `kind` is `text`. Forward it unchanged. The server does **no** decryption and has no key for it.
11. Remove every `TEMP-PLAINTEXT` code path.

### Self-test

12. Add a `selfTest()` function (callable from the browser console) that encrypts to your own public key and decrypts, then confirms that: a flipped ciphertext byte fails, a changed sender or recipient fails, a changed timestamp fails, and a wrong signature fails.

## Must not do

- Do not reuse an IV or an ephemeral key.
- Do not use the raw ECDH output directly as an AES key; always go through HKDF.
- Do not decrypt or display anything before the signature check passes.
- Do not use any crypto library other than Web Crypto.

## Acceptance checks

- [ ] DevTools WebSocket frames show only the envelope fields; no plaintext anywhere.
- [ ] Two browsers exchange messages and see readable text.
- [ ] `selfTest()` reports all tamper cases as failing correctly and the normal case as passing.
- [ ] Re-sending an identical captured envelope is dropped by the `seen` check.
- [ ] A message with `ts` 8 days old, or 10 minutes in the future, is rejected.
- [ ] Searching the server code finds no decrypt call and no plaintext field.
- [ ] Two messages to the same recipient have different `eph` and `iv` values.

## Security checklist

- [ ] Signature verified before decryption.
- [ ] AES-GCM additional data matches between sender and receiver.
- [ ] No `Math.random` anywhere in `static/js/`.

## Commit

`step 6: e2ee with ephemeral ecdh, hkdf, aes-gcm, ecdsa`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_06_encryption.md.
Follow the cryptography specification in main section 8 exactly; do not choose
different parameters. Implement ONLY Step 6. First reply with a short plan listing
the files you will create or change. Wait for my approval before editing. After
implementing, run the acceptance checks and report each one as pass or fail.
Do not start Step 7.
```
