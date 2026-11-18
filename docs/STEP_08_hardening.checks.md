# Step 8: security hardening acceptance results

Validated 19 November 2026 against PROJECT_MAIN.md and STEP_08_hardening.md.

## Acceptance checks

| Required check | Result | Evidence |
| --- | --- | --- |
| Page response contains CSP, HSTS and nosniff | PASS | Checked real HTTPS responses in the Chrome suite and exact header values in server tests. HSTS max-age is 3600 seconds, without subdomain/preload flags. |
| Inline template script is blocked | PASS | A temporary test-server template contains an inline script. Chrome reports a script-src violation and its sentinel remains unset. The test server is then stopped; no experiment was added to production templates. |
| Sixth login attempt within one minute returns 429 | PASS | Five valid-CSRF credential submissions succeed as requests; the sixth returns a generic 429. Varying usernames does not bypass the per-IP limit. GET requests do not consume the POST limit. |
| Correct password refused after five failures | PASS | Failures from several IPs trigger one account-wide lock. Correct credentials are refused with the same generic message. A simulated clock confirms a full 15-minute window from the fifth failure, even when the first failure has aged out, with no extension from blocked requests. |
| Fetch POST without X-CSRFToken rejected | PASS | Missing-token POST and PUT key requests return 400; valid-token key requests succeed. All rendered HTML forms include CSRF tokens. |
| 31st message triggers rate_limited | PASS | Counter is shared across two sockets and persists across reconnect. It resets when the sliding minute expires. |
| Audit includes events without secrets/content | PASS | Server/browser checks inspect actual rotating log files for expected account/key/limit/rejection events and lockout events. Test passwords, Argon2 prefixes, public-key values, ciphertext and message text are absent. Rejected-message entries contain reason only. |
| Forced exception returns a generic page | PASS | HTML and JSON routes return short 500 responses without exception sentinel/trace. A separate Socket.IO exception test verifies no envelope or exception content is printed or written to the audit log. |

## Implementation details

- Flask-Talisman forces HTTPS. CSP uses exactly the specified self-only scripts/styles/default source, restricted WSS origins, local/blob/data images, no frame ancestors, self base URI and form actions. No unsafe directives or wildcard origins were introduced.
- `strict-origin` preserves the origin-only Referer needed by Flask-WTF's strict HTTPS check while avoiding URL-path disclosure. Frame options are DENY; cookie flags remain Secure, HttpOnly and SameSite=Lax.
- Flask-Limiter uses the actual remote connection address and in-memory storage. Limits: login POST 5/minute; register POST 10/hour; directory GET 30/minute across usernames; public-key POST/PUT 10/hour combined.
- Socket.IO uses a locked per-user sliding-minute counter before envelope processing, with idle-entry eviction. Malformed sends count toward the limit; reconnects and additional tabs do not reset it.
- LoginAttempt stores username, IP, success and server time, without credential material. A lock serializes account verification/attempt recording in the specified single-process server. Full dummy verification remains in place for missing or locked users.
- The shared audit module writes allowlisted events and reasons to logs/audit.log with rotation at 1 MiB and three backups. Metadata fields are validated; rejected-message entries exclude all envelope fields. HTTP and Socket.IO exception handlers suppress exception details and SQL bind values.
- Generic HTML/JSON handlers cover 400, 403, 404, 429 and 500. The error template avoids account/database lookups. Error handling is active even in isolated test mode, and the interactive debugger stays disabled.
- Registration/login username validation, password minimum, strict public JWK shape/encoding, encrypted envelope types/size limits, ownership checks and secure SQLite deletion remain enforced.

## Validation

- Full server regression suite: `venv/Scripts/python.exe -m pytest -q -p no:cacheprovider`: **62 passed**.
- Step 8 enabled-limit tests: **17 passed**.
- Actual Chrome HTTPS/WSS suite: `node tests/browser_step6.mjs`: **40 passed, 0 failed**.
- Bandit scans app.py, api.py, auth.py, config.py, events.py, extensions.py, models.py, cleanup.py and audit.py: passed.
- Dependency consistency, JavaScript syntax and Git whitespace checks: passed.

Earlier queue tests explicitly disable only rate counters to exercise 100/200-message limits without waiting. The Step 8 tests enable real limits; the browser suite keeps production CSP/header protection active. All tests use isolated accounts/databases and temporary audit files. Browser inspection/experiment endpoints exist only inside the temporary test server, never in the application.

## Changed files and scope

Application: app.py, extensions.py, config.py, auth.py, api.py, events.py, models.py, audit.py, static/js/chat.js, templates/chat.html, templates/error.html.

Tests/documentation: tests/test_step6.py, tests/test_step8.py, tests/browser_step6.mjs, README.md and this results file.

Startup adds the login_attempts table with create_all; existing account and pending-message data is preserved. HTTP/socket counters are in memory for the specified single-process development server, while account lockouts persist in SQLite. No cryptographic/envelope contracts changed, no dependencies were added, and Step 9 was not implemented.
