# Secure E2EE Messenger

A client-server web messaging app for an information-security course project. Implemented through Step 6: browser-generated identity keys, contact fingerprints, and signed end-to-end encrypted text messages over HTTPS/WSS.

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

## Step 6 behavior

- Open a normal and a private browser session, register different usernames, and enter each other's exact usernames to chat. Messages to offline users are rejected until Step 7 adds the pending queue.
- Compare the displayed fingerprints through a separate trusted channel. A changed contact key blocks messages until **Trust new key** is clicked. Ask the sender to resend a message rejected while a replacement key was untrusted.
- Private keys remain nonextractable in this browser's IndexedDB. If browser data is lost, resetting keys allows new messages; it cannot recover messages encrypted to lost keys.
- Existing IndexedDB data upgrades automatically. Close other chat tabs if an upgrade is blocked. Older contacts without an account owner require an explicit trust review.
- Logging out closes all current chat sockets for that account, including other tabs and devices. They must reconnect after signing in.
- The sender sees **Message sent** after server relay, without implying a recipient rendering receipt. Delivery acknowledgments and stored pending messages start in Step 7.

## Run the checks

Activate the virtual environment, then run:

```powershell
python -m pytest -q
python -m bandit app.py api.py auth.py config.py events.py extensions.py models.py -q
python -m pip check
```

For the full HTTPS/WSS browser acceptance checks, install Node 22+ and Google Chrome and authorize the local mkcert CA installation above. Run from the project root on Windows:

```powershell
node tests/browser_step6.mjs
```

The browser suite launches an isolated in-memory app on port 5443 and separate temporary Chrome sessions. It uses test accounts, preserves the application's real database, and stops its own process trees afterward. Set `CHROME_BIN` if Chrome is installed elsewhere, `CAROOT` if mkcert uses a custom CA directory, or `STEP6_TEST_PORT` if port 5443 is busy. The regular application still uses port 5000.

Browser console crypto self-test:

```javascript
console.table(await e2ee.selfTest());
```

The local Socket.IO 4.8.1 client retains its upstream license and has a documented local adjustment to use Web Crypto randomness for identifiers and reconnect jitter.

See [Step 6 acceptance results](docs/STEP_06_encryption.checks.md).
