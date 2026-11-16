# Step 7: Store Until Delivered, Acknowledge, Delete

**Goal:** a message to an offline user waits on the server (as ciphertext only) and is deleted as soon as the recipient's browser has rendered it. Old undelivered messages expire.
**Depends on:** Step 6.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 9, 11, 14.

## Create or modify

`models.py`, `events.py`, `cleanup.py`, `extensions.py` or `app.py` (SQLite pragma), `static/js/chat.js`.

## Tasks

1. `models.py`: add `PendingMessage` exactly as in main section 9 (`kind`, `ciphertext`, `iv`, `ephemeral_public_key`, `signature`, `client_ts`, `created_at`). Index `recipient_id`.
2. `send_message`: after validation, check the queue limit (`MAX_PENDING_PER_PAIR` rows from this sender to this recipient); if full, ack `{ok:false, error:"queue_full"}`. Otherwise insert the row, commit, ack `{ok:true, id}`, and push `message` to the recipient's room if they are connected.
3. `connect`: after joining the room, send the user's queued messages oldest first (at most 200), one `message` event each, payload `{id, ...envelope}` rebuilt from the row.
4. `ack_message` handler: delete the row **only if** `recipient_id` equals the session user. Return `{ok:true}`; for a wrong or unknown id return `{ok:false}` without revealing which case it was.
5. Client (`chat.js`): after a message has been **rendered successfully**, emit `ack_message` with its id. If verification or decryption failed, do **not** acknowledge; instead show the rejection and let the user choose to dismiss it (a separate `ack_message` from the dismiss button).
6. Client duplicate handling: the Step 6 `seen` check must make a re-delivered message (for example after a dropped connection) render once; it may be acknowledged again safely.
7. `cleanup.py`: a function deleting rows with `created_at` older than `MESSAGE_TTL_DAYS`. Run it at startup and then every hour with `socketio.start_background_task`.
8. SQLite: on every connection, run `PRAGMA secure_delete = ON` (SQLAlchemy `connect` event) so deleted rows are overwritten.
9. Remove the Step 4 "recipient offline" error path.

## Must not do

- Do not delete on send. Delete only on acknowledgement or expiry.
- Do not keep message history in any form after deletion (no archive table, no logs of content).
- Do not let a user acknowledge someone else's message.

## Acceptance checks

- [ ] Alice sends to Bob while Bob is logged out. A row appears in `pending_messages` containing only base64 ciphertext fields.
- [ ] Bob logs in, the message appears decrypted, and the row is gone immediately afterwards (check with DB Browser or `sqlite3`).
- [ ] A tampered ciphertext is rejected by Bob's browser and is **not** acknowledged automatically.
- [ ] With `MESSAGE_TTL_DAYS` temporarily set to a tiny value (for example `0.0007`, about a minute), an undelivered row disappears after the cleanup runs.
- [ ] `PRAGMA secure_delete;` returns 1 on the app's connection.
- [ ] Sending 101 messages from Alice to an offline Bob returns `queue_full` on the 101st.
- [ ] Another user sending `ack_message` with Bob's message id does not delete it.
- [ ] No plaintext column exists in the schema.

## Security checklist

- [ ] Ownership checked on every acknowledgement.
- [ ] Limits enforced server-side.

## Commit

`step 7: pending queue with ack and expiry`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_07_pending_queue.md.
Implement ONLY Step 7. First reply with a short plan listing the files you will
create or change. Wait for my approval before editing. After implementing, run the
acceptance checks and report each one as pass or fail. Do not start Step 8.
```
