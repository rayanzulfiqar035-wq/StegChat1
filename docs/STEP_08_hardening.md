# Step 8: Hardening (Headers, Rate Limits, Logging)

**Goal:** protect the app against common web attacks and leave an audit trail that contains no secrets.
**Depends on:** Step 7.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 10, 11, 14.

## Create or modify

`app.py`, `extensions.py`, `auth.py`, `api.py`, `events.py`, `models.py` (`LoginAttempt`), `config.py`, `logs/` (generated).

## Tasks

1. **Flask-Talisman**: force HTTPS; a Content-Security-Policy with `default-src 'self'`, `script-src 'self'`, `style-src 'self'`, `img-src 'self' blob: data:`, `connect-src 'self' wss://localhost:5000 wss://127.0.0.1:5000`, `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`; HSTS with a short max-age for development; `X-Content-Type-Options: nosniff`; a strict referrer policy. If the app currently has any inline script or style, move it to a static file rather than loosening the policy.
2. **Flask-Limiter** (key by remote address, in-memory storage is fine): login 5 per minute; register 10 per hour; `GET /api/users/<username>/keys` 30 per minute; key upload and reset 10 per hour. Return 429 with a generic JSON or page.
3. **Login lockout**: add `LoginAttempt` and, after 5 failed attempts for one username within 15 minutes, refuse further attempts for that username for 15 minutes, using the same generic error message as before.
4. **Socket event limits**: an in-memory per-user counter allowing at most 30 `send_message` events per minute. Over the limit returns `{ok:false, error:"rate_limited"}`.
5. **CSRF**: confirm `CSRFProtect` covers every POST and PUT, including `fetch` calls (header `X-CSRFToken`). Check that every HTML form includes the token.
6. **Audit log**: standard `logging` with a rotating file `logs/audit.log`. Record: registration, login success and failure (username and IP), logout, key upload and reset, rate-limit hits, lockouts, rejected messages (reason only). **Never** log passwords, hashes, keys, ciphertext, or message content.
7. **Errors**: `DEBUG` off by default; custom 400, 403, 404, 429 and 500 handlers returning short generic messages with no stack traces.
8. **Server-side validation re-check**: username format, password length, JWK shape, envelope size and field types.
9. Cookie flags confirmed: `HttpOnly`, `Secure`, `SameSite=Lax`.

## Must not do

- Do not weaken the CSP to make something work (no `'unsafe-inline'`, no `'unsafe-eval'`, no wildcard origins).
- Do not log request bodies.

## Acceptance checks

- [ ] DevTools, Network, a page response shows the CSP, HSTS and `nosniff` headers.
- [ ] Adding an inline `<script>` to a template in a quick experiment is blocked by the CSP (console error). Remove the experiment afterwards.
- [ ] The 6th login attempt within a minute returns 429.
- [ ] After 5 wrong passwords, even the correct password is refused for that username, with the same generic message.
- [ ] A `fetch` POST without `X-CSRFToken` is rejected.
- [ ] Sending 31 messages in a minute triggers `rate_limited`.
- [ ] `logs/audit.log` contains the expected events; searching it for a test password, a ciphertext string or message text finds nothing.
- [ ] Forcing an exception shows a generic error page, not a stack trace.

## Security checklist

- [ ] CSP has no unsafe directives.
- [ ] Logs contain no secrets or content.

## Commit

`step 8: hardening headers, limits, audit log`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_08_hardening.md.
Implement ONLY Step 8. First reply with a short plan listing the files you will
create or change. Wait for my approval before editing. After implementing, run the
acceptance checks and report each one as pass or fail. Do not start Step 9.
```
