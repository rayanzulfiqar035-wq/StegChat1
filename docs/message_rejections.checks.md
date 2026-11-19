# Offline delivery after a key reset

Read-only queue metadata showed an encrypted PNG created before its recipient's
key reset. No payloads, private keys or password hashes were inspected. The
message remains encrypted for the old recipient identity; resetting keys does
not make that delivery decryptable with the new identity.

The recovery is to compare the recipient's current fingerprint through a
trusted channel and send a fresh encrypted message using a fresh PNG cover.
The server cannot recover the missing private key or re-encrypt the message.

The UI now attaches a fixed explanation and recovery advice to each rejected
delivery, rather than relying on a generic notice and a shared status line.
Decryption failures explain the key-reset case; signature failures, changed
sender keys, expired/future timestamps, lookup limits and expired sessions have
separate explanations. Unknown errors use a fixed generic explanation. No
payload or arbitrary error text is displayed. Redelivery updates the existing
notice instead of adding another notice for the same delivery ID.

Signature verification, timestamps, replay checks, decryption, rendering and
recipient-owned acknowledgment retain their order. Failed decryption neither
acknowledges a row nor resets keys. The existing explicit dismiss action is
retained. No production messages, identities or database rows were modified.

## Validation

- Real Chrome HTTPS/WSS suite: **85 passed, 0 failed**.
- Reproduced an offline encrypted PNG followed by loss and explicit reset of
  the recipient identity. The old PNG stays queued, is not rendered, and shows
  key-reset and fresh-cover guidance.
- Simulated HTTP 429 during sender-key lookup. The message stays queued and
  shows the temporary lookup reason; retrying after the failure clears decrypts
  and acknowledges it normally.
- Existing offline PNG delivery with unchanged keys, tampered-PNG rejection,
  explicit dismissal, replay handling and expiry checks still pass.
- JavaScript syntax and Git whitespace checks pass.

Changes: `static/js/chat.js`, `static/css/interface.css`,
`tests/browser_step6.mjs`, `README.md` and this check record.
