# Step 3: HTTPS and Secure Cookies

**Goal:** the app runs only over HTTPS (and WSS later), with a locally trusted certificate and secure cookies.
**Depends on:** Step 2.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 5, 7, 14.

**Why this matters beyond security:** the browser's Web Crypto API (`crypto.subtle`) only exists on secure origins (`https://` or `localhost`). Without HTTPS, encryption code fails on other addresses.

## Create or modify

`app.py`, `config.py`, `.env.example`, `certs/` (generated, not committed), `README` notes for the team.

## Tasks (manual, done by the team)

1. Install mkcert (Windows: `choco install mkcert` or `scoop install mkcert`; macOS: `brew install mkcert`; Linux: install `libnss3-tools` and the mkcert binary).
2. Run `mkcert -install` once to trust the local certificate authority.
3. From the project folder run:
   `mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1 ::1`

## Tasks (AI agent)

1. `config.py`: read `SSL_CERT` and `SSL_KEY`. Refuse to start if either file is missing, with a message telling the user to run the mkcert commands above.
2. `app.py`: start the server with `socketio.run(app, host="127.0.0.1", port=5000, ssl_context=(cert, key), allow_unsafe_werkzeug=True)`. If the installed Flask-SocketIO version does not accept `ssl_context`, check its documentation and use the supported way to pass the certificate and key; do not fall back to HTTP.
3. Set `SESSION_COOKIE_SECURE=True`.
4. Do not start any plain-HTTP listener.
5. Add a short "Run the app" section to the project README: install, mkcert, `.env`, `python app.py`, open `https://localhost:5000`.

## Must not do

- Do not commit anything in `certs/`.
- Do not disable certificate verification anywhere.
- Do not hard-code certificate paths; use the `.env` values.

## Acceptance checks

- [ ] `https://localhost:5000/login` loads with a padlock and no certificate warning.
- [ ] `http://localhost:5000` does not serve the app.
- [ ] The session cookie now shows the `Secure` flag.
- [ ] Starting with a missing certificate file prints the helpful message and exits.
- [ ] `git status` shows `certs/` ignored.

## Notes

- To test from a second device on your network you must install mkcert's root certificate on that device, and use the computer's IP address in the certificate and in the allowed origins (Step 4). Using two browsers (one normal, one private window) on one computer is simpler.

## Commit

`step 3: https with mkcert`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_03_https.md.
I have already generated the mkcert certificate files in certs/.
Implement ONLY the AI agent tasks of Step 3. First reply with a short plan,
wait for my approval, then implement, run the acceptance checks, and report
each as pass or fail. Do not start Step 4.
```
