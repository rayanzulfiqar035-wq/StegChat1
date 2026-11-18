# Secure E2EE Messenger

A client-server web messaging app for an information-security course project. Implemented through Step 9: browser identity keys, encrypted chat and delivery queue, web security hardening, and an opt-in standalone PNG steganography lab.

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

- Open a normal and a private browser session, register different usernames, and enter each other's exact usernames to chat. Once a recipient has published keys, messages can be sent while they are offline; ciphertext waits until their browser reconnects.
- Compare the displayed fingerprints through a separate trusted channel. A changed contact key blocks messages until **Trust new key** is clicked. Ask the sender to resend a message rejected while a replacement key was untrusted.
- Private keys remain nonextractable in this browser's IndexedDB. If browser data is lost, resetting keys allows new messages; it cannot recover messages encrypted to lost keys.
- Existing IndexedDB data upgrades automatically. Close other chat tabs if an upgrade is blocked. Older contacts without an account owner require an explicit trust review.
- Logging out closes all current chat sockets for that account, including other tabs and devices. They must reconnect after signing in.
- The sender sees **Message sent** after the server stores the envelope. The recipient acknowledges it after verification, decryption and rendering; only then is the queued row deleted. Reconnection delivers the oldest pending messages first, up to 200 per connection, without rendering accepted duplicates twice.
- Rejected messages remain pending. **Dismiss rejected message** explicitly deletes a rejected delivery; no rejected content is displayed. Reconnect to retry after resolving a key-trust issue.
- The queue allows 100 pending messages per sender/recipient pair by default; further sends return `queue_full`. Undelivered messages expire after `MESSAGE_TTL_DAYS` (default 7 days). Cleanup runs at startup and hourly. Fractional days such as `0.0007` can be used for expiry testing.

## Run the checks

Activate the virtual environment, then run:

```powershell
python -m pytest -q
python -m bandit app.py api.py auth.py config.py events.py extensions.py models.py cleanup.py audit.py -q
python -m pip check
```

For the Step 6-9 HTTPS/WSS browser acceptance checks, install Node 22+ and Google Chrome and authorize the local mkcert CA installation above. Run from the project root on Windows:

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

Open `https://localhost:5000/stego-lab` or use the **Stego lab** navigation link. Without the flag, this URL returns 404; when enabled it still requires login. The implementation does not change your `.env` automatically.

Choose a fully opaque PNG between 256 and 4096 pixels per side, enter text and a 64-character hexadecimal secret key (or generate a random key), and select replacement or matching mode. Embed, download the PNG, then choose that downloaded file under Extract and use the same key. The page shows capacity use and the number of changed RGB channels, with original/stego previews for comparison. Run the self-test button to check the library in your browser.

Only RGB least significant bits carry the frame; alpha is preserved. Usage includes a four-byte length header: above 10% shows a warning, and above 50% is refused. A wrong key can fail or produce garbage because this standalone raw-byte frame is not authenticated. Steganography here hides bytes without encrypting them; PNG conversion to JPEG is unsupported and extraction is rejected. Images, text and keys stay local to the page, with no server upload or chat integration.

See [Step 9 acceptance results](docs/STEP_09_stego_core.checks.md).

Tests for earlier steps explicitly disable rate counters when exercising large queues; `tests/test_step8.py` checks the actual enabled HTTP/socket limits. The browser suite keeps CSP and other headers active and verifies inline-script blocking in a temporary test-only page.
