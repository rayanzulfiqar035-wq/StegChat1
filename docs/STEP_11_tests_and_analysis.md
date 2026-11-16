# Step 11: Tests, Scans and Analysis

**Goal:** prove the defences work and collect the evidence for the report.
**Depends on:** Step 10 (or Step 8 if stego is skipped).
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 9, 10, 11.

Test only your own app, on your own computer.

## Create or modify

`tests/` (pytest files), `tools/stego_analysis.py`, `evidence/` (screenshots and outputs; do not commit anything secret).

## Part A: Automated tests (AI agent)

Write pytest tests using Flask's test client with a temporary database and a test `SECRET_KEY`:

1. Registration: valid user succeeds; duplicate (case-insensitive) fails; short password fails; stored hash starts with `$argon2id$` and never equals the password.
2. Login: success and failure; identical error text for unknown user and wrong password; lockout after 5 failures.
3. Authorisation: `/chat` and `/api/*` need login; `GET /api/users/<name>/keys` for an unknown user returns 404.
4. Key upload: valid JWK accepted; a JWK containing `d` rejected; a wrong curve rejected; second `POST /api/keys` returns 409.
5. CSRF: POST and PUT without a token are rejected.
6. Pending queue: row created on send; deleted on acknowledgement by the recipient; not deleted when acknowledged by another user; expiry function removes old rows; the 101st queued message is refused.
7. Size limits: text and stego envelopes above the limits are refused.
8. Schema check: no column in any table is named like plaintext, message text or private key.
9. Rate limiting: the 6th login within a minute returns 429.
10. Audit log: after a failed login, the log contains the event and does not contain the submitted password.

## Part B: Static and dependency checks (run by the team)

- `bandit -r . -x ./venv,./tests`; fix real findings and note justified ones in the report.
- `pip-audit`; update or document any vulnerable dependency.

## Part C: Manual evidence (team)

| Tool | What to capture |
| --- | --- |
| Browser DevTools, Network and WS | WebSocket frames contain only ciphertext, IV, ephemeral key and signature |
| DB Browser for SQLite | `users` holds hashes and public keys only; `pending_messages` holds unreadable base64 and is empty after delivery |
| Wireshark (loopback; Npcap on Windows) | Traffic to port 5000 is TLS; payloads are unreadable |
| OWASP ZAP (baseline scan against `https://localhost:5000`) | Report with no high-severity issues, or a note on each remaining finding |
| Attack attempts | XSS payload rendered as text; SQL injection string in the login form rejected; many wrong passwords get 429; one flipped byte makes decryption or the signature check fail |

Save screenshots in `evidence/` with clear names.

## Part D: Stego analysis script (AI agent)

`tools/stego_analysis.py original.png stego.png` using Pillow and NumPy:

1. Print image size, number of changed channel values, and the percentage changed.
2. Save an amplified difference image (changed channels shown in white) as `evidence/diff.png`.
3. Save the least-significant-bit plane of both images as black and white images.
4. Compute the **pairs-of-values chi-square statistic** for each image (histogram `h` of channel values 0 to 255; for each pair `(2k, 2k+1)` the expected count is `(h[2k] + h[2k+1]) / 2`; sum `(h[2k] - expected)^2 / expected` over pairs with expected above 0). Print both values. Embedding evens out each pair, so a much **lower** statistic in the stego image than in the original suggests hidden data.
5. Document honestly in the script header: whole-image statistics only detect heavily filled images. For the report, run two experiments: a low-fill message (under 10%), which this test will usually **not** flag, and a deliberately high-fill message (around 50%), which it will. This demonstrates both the stealth and its limits.

## Must not do

- Do not point scanners at anything except your own local instance.
- Do not commit `evidence/` files that show real secrets.

## Acceptance checks

- [ ] `pytest` passes completely.
- [ ] Bandit and pip-audit output saved in `evidence/`.
- [ ] Every row of the Part C table has at least one screenshot or saved output.
- [ ] `tools/stego_analysis.py` runs on a cover and stego pair and produces the files above.

## Commit

`step 11: tests and analysis`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_11_tests_and_analysis.md.
Implement ONLY Parts A and D (the tests and the analysis script). First reply with a
short plan listing the files you will create. Wait for my approval before editing.
After implementing, run pytest and report each result. Do not start Step 12.
```
