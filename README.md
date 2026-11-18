# Secure E2EE Messenger

A client-server web messaging app for an information-security course project. Implemented through Step 10, plus Step 11 Parts A and D: security regression tests and stego analysis. Includes encrypted text and PNG stego chat, temporary delivery queues, web security hardening, and an opt-in standalone steganography lab.

## Run the App

### 1. Prerequisites & Virtual Environment
Ensure Python 3.10+ is installed. Create and activate a virtual environment, then install dependencies:
```bash
python -m venv venv
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. TLS Certificates (mkcert)
The application runs strictly over HTTPS. Install [mkcert](https://github.com/FiloSottile/mkcert) and generate locally trusted certificates:
```bash
# 1. Install mkcert local CA (run once)
mkcert -install

# 2. Generate certificates in certs/
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1 ::1
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and configure a strong `SECRET_KEY`:
```bash
cp .env.example .env
```
Generate a random secret key and set it in `.env`:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Start the Server
Run the Flask server:
```bash
python app.py
```

Open your browser and navigate to:
```
https://localhost:5000
```

If the browser reports `ERR_CERT_AUTHORITY_INVALID`, install the existing local mkcert CA with `mkcert -install`, then restart the browser. This changes the computer's certificate trust store; do it only on your development computer with authorization. Certificate verification must stay enabled.

## Chat and delivery behavior

- The website opens the login page directly, with a **Create an account** link.
  Once signed in, use the collapsible sidebar to switch between **Chat** and
  **Stego**. The sidebar remembers only its layout preference. On small screens
  it starts collapsed; Escape closes the expanded drawer.
- **Send with stego** opens the transport selector. **Image** opens the darker
  PNG composer; **Audio** and **Text** open clearly marked, disabled previews.
  A valid PNG is required to send from the image composer. Normal Chat continues
  to send encrypted text. The image composer also displays incoming messages
  using the existing verification, decryption and acknowledgment behavior.
- Use **Phonebook** in Chat or the image composer to send a request by exact
  username. The recipient must choose **Accept**; then both users become
  approved contacts. Pending requests do not permit messaging. You can decline
  incoming requests, cancel outgoing requests, or remove approved contacts.
  Removal blocks further sends and queued delivery in both directions, including
  attempts that bypass the browser UI. Fingerprint verification still applies.
- Open a normal and a private browser session, register different usernames,
  send and accept a contact request, then choose the approved contact to chat.
  Once a recipient has published keys, messages can be sent while they are
  offline; ciphertext waits until their browser reconnects.
- Compare the displayed fingerprints through a separate trusted channel. A changed contact key blocks messages until **Trust new key** is clicked. Ask the sender to resend a message rejected while a replacement key was untrusted.
- Private keys remain nonextractable in this browser's IndexedDB. If browser data is lost, resetting keys allows new messages; it cannot recover messages encrypted to lost keys.
- Offline deliveries encrypted before a recipient key reset still need the old
  private key. Ask the sender to send the message again using the current
  verified fingerprint; image messages need a fresh cover PNG. Each rejected
  delivery now shows its cause and recovery advice beside the dismiss button.
  Temporary lookup failures can be retried by refreshing after the limit or
  connection problem clears. Rejected deliveries are retained until explicitly
  dismissed or expired.
- Existing IndexedDB data upgrades automatically. Close other chat tabs if an upgrade is blocked. Older contacts without an account owner require an explicit trust review.
- Logging out closes all current chat sockets for that account, including other tabs and devices. They must reconnect after signing in.
- The sender sees **Message sent** after the server stores the envelope. The recipient acknowledges it after verification, decryption and rendering; only then is the queued row deleted. Reconnection delivers the oldest pending messages first, up to 200 per connection, without rendering accepted duplicates twice.
- Rejected messages remain pending. **Dismiss rejected message** explicitly deletes a rejected delivery; no rejected content is displayed. Reconnect to retry after resolving a key-trust issue.
- The queue allows 100 pending messages per sender/recipient pair by default; further sends return `queue_full`. Undelivered messages expire after `MESSAGE_TTL_DAYS` (default 7 days). Cleanup runs at startup and hourly. Fractional days such as `0.0007` can be used for expiry testing.

The phonebook adds only request/approval metadata in `phonebook_contacts`.
Starting the app adds this table without recreating the existing database.
Existing accounts are not automatically approved. Previously queued ciphertext
is withheld until the users approve a contact request and reconnect; removed
contacts' queued rows remain encrypted until expiry or explicit recipient
dismissal, and become eligible again if a new request is accepted.

The authenticated API is `GET/POST /api/contacts`,
`POST /api/contacts/<username>/accept`, and `DELETE /api/contacts/<username>`.
Changes require CSRF protection and share a 30/hour limit. The phonebook list
is private to the signed-in account. Contact changes notify only the affected
accounts to refresh their lists. Encryption parameters and envelope fields are
unchanged.

## Run the checks

Activate the virtual environment, then run:

```powershell
python -m pip install -r requirements-analysis.txt
python -m pytest -q
python -m bandit app.py api.py auth.py config.py events.py extensions.py models.py cleanup.py audit.py -q
python -m pip check
```

Pillow and NumPy are used by the offline Step 11 analysis tool and its tests;
they are pinned separately from the application dependencies.

For the Step 6-10 HTTPS/WSS browser acceptance checks, install Node 22+ and Google Chrome and authorize the local mkcert CA installation above. Run from the project root on Windows:

```powershell
node tests/browser_step6.mjs
```

Position-stream algorithm and capacity checks:

```powershell
node --test tests/test_stego.mjs
```

The browser suite launches an isolated in-memory app on port 5443 and separate temporary Chrome sessions. It uses test accounts, preserves the application's real database, and stops its own process trees afterward. Set `CHROME_BIN` if Chrome is installed elsewhere, `CAROOT` if mkcert uses a custom CA directory, or `STEP6_TEST_PORT` if port 5443 is busy. The regular application still uses port 5000.

The same browser command now covers Step 9 with the lab enabled only in its temporary server, including real PNG download/extraction, eleven self-tests, PNG validation, capacity limits, and checks that lab inputs stay off the network.

Browser console crypto self-test:

```javascript
console.table(await e2ee.selfTest());
```

The local Socket.IO 4.8.1 client retains its upstream license and has a documented local adjustment to use Web Crypto randomness for identifiers and reconnect jitter.

See [Step 6 acceptance results](docs/STEP_06_encryption.checks.md).
See [Step 7 acceptance results](docs/STEP_07_pending_queue.checks.md).

See [Step 8 acceptance results](docs/STEP_08_hardening.checks.md).

## Step 11 analysis

Install the analysis dependencies before running the full test suite:

```powershell
python -m pip install -r requirements-analysis.txt
python tools/stego_analysis.py original.png stego.png
```

The tool writes `diff.png`, black-and-white RGB LSB planes and `report.json`
under `evidence/`; use `--output-dir` to keep experiments separate. The saved
low-fill and high-fill experiments use real browser encryption with synthetic
messages. See [evidence and reproduction commands](evidence/README.md) and
[Step 11 results](docs/STEP_11_tests_and_analysis.checks.md). Parts A and D are
implemented; the team's Part B scans and Part C captures remain pending.

## Security hardening

The app forces HTTPS and sends a strict Content Security Policy, `nosniff`, frame protection, a one-hour development HSTS policy, and a strict-origin referrer policy. Scripts and styles are served locally; inline scripts and styles are blocked.

HTTP limits are keyed by the connection IP: login submissions 5/minute, registration submissions 10/hour, public-key lookups 30/minute across usernames, and key upload/reset 10/hour combined. Message sends are limited to 30/minute per user across tabs and reconnects. HTTP limits return 429; excess socket sends return `rate_limited`.

Five wrong passwords for a username within 15 minutes start a full 15-minute lock from the fifth failure. Blocked requests keep the generic login error and do not extend the lock. Login-attempt metadata is stored in SQLite, so the account lock survives server restarts. The in-memory HTTP/socket counters reset on restart, as intended for the single-process development server.

Security events rotate in `logs/audit.log` (1 MiB per file, three backups). Events include account/key activity, lockouts, rate-limit hits, and rejection reasons. Passwords, hashes, key values, ciphertext and message text are excluded. Error pages and socket errors return generic messages.

## Standalone steganography lab (Step 9)

The lab is disabled by default. To enable it locally, set this existing flag in `.env`, restart the app, and sign in:

```dotenv
STEGO_LAB=1
```

Open `https://localhost:5000/stego-lab` or use the **Local lab** sidebar link. Without the flag, this URL returns 404; when enabled it still requires login. The implementation does not change your `.env` automatically.

Choose a fully opaque PNG between 256 and 4096 pixels per side, enter text and a 64-character hexadecimal secret key (or generate a random key), and select replacement or matching mode. Embed, download the PNG, then choose that downloaded file under Extract and use the same key. The page shows capacity use and the number of changed RGB channels, with original/stego previews for comparison. Run the self-test button to check the library in your browser.

Only RGB least significant bits carry the frame; alpha is preserved. Usage includes a four-byte length header: above 10% shows a warning, and above 50% is refused. A wrong key can fail or produce garbage because this standalone raw-byte frame is not authenticated. Steganography here hides bytes without encrypting them; PNG conversion to JPEG is unsupported and extraction is rejected. Images, text and keys stay local to the page, with no server upload or chat integration.

See [Step 9 acceptance results](docs/STEP_09_stego_core.checks.md).

## Encrypted PNG messages in chat (Step 10)

In Chat, choose **Send with stego**, then **Image**. On the image page, enter the recipient, choose a cover PNG, write your message, and choose **Encrypt & send image**. The PNG must be fully opaque and 256–4096 pixels per side. The preview and capacity information stay local to the browser. **Remove image** clears the attachment; the image page requires a valid cover before sending again. Use **Chat** in the sidebar to send normal encrypted text. This feature works independently of the opt-in lab flag.

Use each cover image once. The page blocks an identical file already transmitted during the current page session, including unsuccessful/uncertain delivery attempts, and clears attachments after successful sends. Across reloads or devices, choose a genuinely fresh cover yourself. Usage above 10% shows a warning; above 50% is refused, counting the length header, IV and authentication tag. The final exported PNG is limited to `MAX_STEGO_BYTES` (default 3 MiB). Stego sends are limited to 5/minute per account within the existing 30/minute overall send limit.

The browser encrypts the text before embedding it, using independent HKDF keys for AES-GCM and stego positions. A signature covers the PNG hash and message metadata. The recipient verifies the signature before extraction/decryption and rendering. The server stores/relays the PNG bytes unchanged, including while the recipient is offline, and deletes the row on the recipient's acknowledgment. Rejected images remain pending until explicitly dismissed or expired. Re-saving or converting a carrier invalidates its signature; JPEG is unsupported.

See [Step 10 acceptance results](docs/STEP_10_stego_integration.checks.md).

Tests for earlier steps explicitly disable rate counters when exercising large queues; `tests/test_step8.py` checks the actual enabled HTTP/socket limits. The browser suite keeps CSP and other headers active and verifies inline-script blocking in a temporary test-only page.
