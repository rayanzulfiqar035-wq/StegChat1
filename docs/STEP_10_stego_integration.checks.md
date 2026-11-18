# Step 10: encrypted steganography in chat

Implemented against PROJECT_MAIN.md and STEP_10_stego_integration.md.

## Acceptance checks

| Required check | Result | Evidence |
| --- | --- | --- |
| Alice sends offline; Bob logs in, reads, and acknowledges deletion | PASS | Chrome sends through the real attachment/message controls while Bob is logged out. The pending row holds the exact PNG base64 with a null IV. Bob logs in, verifies/extracts/decrypts/renders the message and the row disappears. |
| WSS carrier opens and looks like the cover | PASS | Actual envelope PNG decodes normally. Browser pixel comparison against the selected cover confirms alpha is unchanged and RGB changes are at most one level. The outer envelope has exactly the specified stego fields. |
| One changed PNG byte causes signature failure | PASS | A test-only hook flips one byte of a queued PNG. Bob reconnects, reports bad signature, renders no message, and does not acknowledge that row. The hook exists only in the isolated test server. |
| Third account cannot read the captured image | PASS | The third account's own ECDH private key fails extraction/decryption of the captured envelope. A separate independent Web Crypto reference confirms that even using the recovered stego-position key as an AES key fails the GCM tag check. |
| JPEG re-save fails extraction | PASS | The actual encrypted PNG is converted to JPEG; decrypt/extract rejects it. Changing the image also invalidates its signed hash. |
| PNG above MAX_STEGO_BYTES is refused clearly | PASS | Server tests check decoded-byte boundaries, the browser submits an over-3-MiB carrier and receives `image too large`, and the crypto sender rejects oversized exported PNGs before transmission. Chat maps this failure to a clear image-limit explanation. |
| Fresh ephemeral keys produce different positions; UI warns against reuse | PASS | Two direct crypto calls with the same cover produce different ephemeral keys, IVs and first 100 positions under independently derived recipient keys. The normal UI warns to use each cover once, clears successful attachments, and refuses an identical previously transmitted file. Direct repeated-cover calls are test-only. |

## Security and implementation

Sending derives one ECDH shared secret with the recipient's long-term public key. HKDF-SHA256 uses 32 zero salt bytes for two purposes: `message-encryption` produces a nonextractable AES-256-GCM key; `stego-positions` produces 32 position-key bytes kept only in browser memory. The original text derivation shares the common helpers and remains compatible.

Stego encryption uses a fresh 12-byte random IV, a 128-bit tag and exact AAD `v1|stego|sender|recipient|ts`. The Step 9 library embeds `IV || ciphertext-with-tag`. The sender signs UTF-8 JSON.stringify of `["v1","stego",sender,recipient,ts,eph,sha256_hex_of_png_bytes]` using ECDSA-SHA256. Neither the IV nor ciphertext nor position key appears as an outer stego-envelope field.

Receive order remains: structural checks, recipient check, sender key fetch/TOFU, signature over recomputed PNG hash, timestamp, replay store, key derivation/extraction/GCM decryption, textContent render, seen-record commit and acknowledgment. PNG decoding occurs only after signature/timestamp/replay acceptance. Rejected deliveries retain the existing explicit-dismiss behavior. Optional thumbnails were omitted to avoid displaying unverified carriers or retaining extra image URLs.

The server checks exact field sets/types, canonical standard base64, sender identity, recipient existence, point/signature lengths, decoded PNG size and magic bytes. It never decodes, resizes or re-encodes pixels. PendingMessage uses the existing ciphertext column for PNG base64 and a null IV; queued stego envelopes are rebuilt with `img`, without text-only fields. No schema migration or database recreation is needed.

Stego has a separate per-user sliding-minute cap of 5 sends in addition to the general cap of 30, shared across reconnects/tabs. Both message kinds share the pair queue cap and recipient-owned ACK deletion. Socket.IO accepts at least 5,000,000 bytes; larger configured PNG limits adjust its buffer and the HTTP body limit for base64 expansion. Audit reasons are allowlisted, with no PNG/base64/key content logged.

Cover usage includes 4 length bytes, 12 IV bytes, 16 GCM tag bytes and UTF-8 message bytes. The UI warns strictly above 10%; the core refuses above 50%. Attachment changes invalidate in-flight sends. The page reserves a cover on any transmission and refuses identical file bytes afterward, even after a negative/uncertain ACK. The visible note also applies across sessions/devices; the local set is not a global cover registry.

## Validation

- `venv/Scripts/python.exe -m pytest -q -p no:cacheprovider`: **79 passed**.
- `node --test tests/test_stego.mjs`: **5 passed**.
- `node tests/browser_step6.mjs`: **68 passed, 0 failed**.
- Bandit application scan, dependency consistency, JavaScript syntax and Git whitespace checks: passed.

The independent browser reference verifies HKDF labels, salt, AAD, signed image-hash bytes and the actual hidden encrypted frame. Additional checks cover over-10% warnings, over-50% encrypted payload refusal, cover reuse, image size, unchanged queued bytes, stricter rate limits, shared queue caps and rejection logs containing reason only. Existing text-chat, authentication, key-trust, replay, expiry and standalone-lab regressions pass. Tests use isolated accounts and temporary/in-memory databases; no real application accounts or messages are modified.

## Files changed

Application: static/js/crypto.js, static/js/chat.js, templates/chat.html, events.py, models.py, config.py, app.py and audit.py.

Validation/documentation: tests/test_step10.py, tests/browser_step6.mjs, README.md and this results file.

The Step 9 steganography implementation is reused without duplication. No dependencies or new HTTP API endpoints were added to the application. Step 11 was not implemented.
