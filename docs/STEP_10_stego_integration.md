# Step 10: Steganography Inside the Chat

**Goal:** a user can attach a cover PNG and a secret message. The recipient's browser extracts and decrypts it. The server only relays an ordinary-looking image.
**Depends on:** Step 9.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 8, 9, 11, 12, 14.

## Create or modify

`static/js/crypto.js`, `static/js/stego.js` (only if needed), `static/js/chat.js`, `templates/chat.html`, `events.py`, `config.py`, `app.py`.

## Tasks

### Sending

1. UI: an "Attach cover image" control (PNG only) and the message box; a clear warning if the usage is above 10% of capacity, and a hard refusal above 50%.
2. Create a new ephemeral ECDH pair and derive the shared secret with the recipient's long-term ECDH public key (as in Step 6).
3. From the same shared secret, derive **two independent keys** with HKDF (salt = 32 zero bytes): the AES key with info `message-encryption`, and 32 bytes of stego key with info `stego-positions`.
4. Encrypt the text with AES-GCM (random 12-byte IV, additional data `v1|stego|<sender>|<recipient>|<ts>`). Payload to embed = `iv (12 bytes) || ciphertext-with-tag`.
5. `embed(coverImage, payload, stegoKey)`, then take the resulting PNG bytes.
6. Compute `sha256_hex` of the PNG bytes and sign `JSON.stringify(["v1","stego",sender,recipient,ts,eph,sha256_hex])` with the ECDSA private key.
7. Send the envelope `kind: "stego"` with `eph`, `img` (base64 PNG) and `sig`.

### Receiving

8. In this order: TOFU key check, recompute the SHA-256 of the received PNG bytes and verify the signature, check `ts`, check `seen`, derive the AES and stego keys, `extract` the payload, split off the IV, AES-GCM decrypt, render the text with `textContent`. Optionally show the received image as a small thumbnail using a `blob:` URL.
9. Acknowledge only after rendering (as in Step 7). A failed check shows "message rejected" with a short reason.

### Server

10. Accept `kind: "stego"` in `send_message`: base64 decode, size at most `MAX_STEGO_BYTES`, the PNG magic bytes are present, `eph` and `sig` are valid base64. Store `img` in the `ciphertext` column with `iv` null. **Never decode, resize or re-encode the image.** Raise `max_http_buffer_size` (Socket.IO) to at least 5 MB so the envelope fits.
11. Apply a stricter rate limit to stego messages (for example 5 per minute per user) and keep the queue limits from Step 7.
12. Messages of kind `stego` are pushed and acknowledged exactly like text messages.

## Must not do

- Do not let the server process the image.
- Do not use the same derived key for AES and for stego positions.
- Do not reuse a cover image; add a visible note in the UI that each cover image should be used once.

## Acceptance checks

- [ ] Alice sends a stego message to an offline Bob; Bob logs in and reads it; the row is deleted after acknowledgement.
- [ ] The image in DevTools (or saved from the WebSocket frame) looks like the original cover and opens normally.
- [ ] Changing a single byte of the PNG in the queued envelope makes Bob's signature check fail.
- [ ] A third user cannot read the message even if they obtain the image (wrong keys, GCM check fails).
- [ ] Re-saving the image as JPEG and trying to extract fails.
- [ ] An image above `MAX_STEGO_BYTES` is refused with a clear error.
- [ ] Two stego messages with the same cover image use different positions (different ephemeral keys), and the UI warns against reusing covers.

## Security checklist

- [ ] The signature covers the image hash, so the image cannot be swapped.
- [ ] The server never touches pixel data.

## Commit

`step 10: stego messages in chat`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_10_stego_integration.md.
Implement ONLY Step 10. Reuse the key derivation and verification code from Step 6
and the library from Step 9; do not duplicate it. First reply with a short plan
listing the files you will create or change. Wait for my approval before editing.
After implementing, run the acceptance checks and report each one as pass or fail.
Do not start Step 11.
```
