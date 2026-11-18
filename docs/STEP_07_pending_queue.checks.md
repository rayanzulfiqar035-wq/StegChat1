# Step 7: pending queue acceptance results

Validated 19 November 2026 against PROJECT_MAIN.md and STEP_07_pending_queue.md.

## Acceptance checks

| Required check | Result | Evidence |
| --- | --- | --- |
| Offline Bob's message is stored as ciphertext | PASS | Server test sends before Bob logs in and inspects the ORM row; browser test sends with Bob disconnected and inspects the saved base64 ciphertext. |
| Bob reconnects, decrypts/renders, and row disappears | PASS | Actual Chrome HTTPS/WSS test confirms rendered text followed by deletion from the isolated server database. |
| Tampered ciphertext is rejected without automatic acknowledgment | PASS | Browser confirms the tampered delivery remains stored, then verifies deletion only after an explicit dismiss click. |
| Tiny TTL removes an undelivered row after cleanup | PASS | Server test uses `0.0007` days with a server-created timestamp two minutes in the past; cleanup deletes only the expired row. Browser expiry check also removes an undelivered encrypted message. No minute-long sleep is needed. |
| SQLite secure_delete returns 1 | PASS | Checked on initial and newly opened file-backed SQLite connections. |
| 101st pending message returns queue_full | PASS | Server test stores 100 messages to offline Bob, rejects the 101st, and confirms a different recipient pair can still receive a queued message. |
| Another user cannot acknowledge Bob's message | PASS | Both sender and third-party ACKs return the same false result as an unknown ID; row remains. |
| Schema has no plaintext message column | PASS | PendingMessage schema and stored envelope inspected; only ciphertext, public ephemeral key, signature and delivery metadata are persisted. |

## Implementation

PendingMessage has the specified columns, an indexed recipient foreign key, and SQLite autoincrement IDs so a late acknowledgment cannot delete a newer message reusing an ID. All message-data queries use SQLAlchemy ORM. The constant `PRAGMA secure_delete = ON` in the SQLAlchemy connection hook implements Step 7's explicit SQLite requirement.

Sending commits ciphertext before emitting or returning success. Queue count and insertion are serialized for the specified single-process threading server. Reconnect joins the recipient room and delivers the oldest 200 queued envelopes, preserving their signed fields. ACK deletion includes recipient ownership in its predicate; wrong, malformed and unknown IDs reveal no ownership information.

The browser records accepted signatures after rendering, then acknowledges the delivery. A duplicate can be acknowledged without rendering again. Dropped acknowledgments leave ciphertext pending for reconnect. Verification/decryption failures expose no payload contents and provide a separate explicit dismissal button.

Cleanup deletes by server-created timestamps at startup and hourly through Socket.IO's background-task API. Tests disable the real background thread and separately verify the hourly scheduling path. Fractional positive TTLs are supported. Existing user tables are preserved; startup adds the pending table using create_all, without deleting or recreating the development database.

## Validation and scope

- Server regression suite: `venv/Scripts/python.exe -m pytest -q -p no:cacheprovider`: **45 passed** (including a database-failure regression that checks rollback, no relay, and no ciphertext output).
- Real browser suite: `node tests/browser_step6.mjs` (now covers Steps 6 and 7): **37 passed, 0 failed**.
- Bandit scan of application modules including cleanup.py: passed.
- Dependency consistency, JavaScript syntax checks, and Git whitespace check: passed.

Tests use temporary accounts and in-memory/file-backed temporary databases. Browser inspection endpoints exist only in the test server string, never in the application. Existing application accounts/messages and certificate trust settings were not changed for this step.

Files changed: models.py, events.py, cleanup.py, extensions.py, app.py, config.py, static/js/chat.js, tests/test_step6.py, tests/test_step7.py, tests/browser_step6.mjs, README.md, and this results file.

No Step 8 hardening or later features were implemented. Sender status confirms server acceptance, not a recipient read receipt. A connection delivers at most 200 queued messages as specified; remaining messages can be received on a subsequent reconnect.
