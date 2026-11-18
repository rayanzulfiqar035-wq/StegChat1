# Step 11: tests and stego analysis

Implemented the AI-assigned Parts A and D of STEP_11_tests_and_analysis.md,
following PROJECT_MAIN.md. Parts B and C remain assigned to the team. Step 12
has not been started. Application routes, UI, database schema, cryptographic
contracts and the real application database are unchanged.

## Acceptance status

| Required check | Result | Evidence |
| --- | --- | --- |
| Complete pytest suite passes | PASS | 96 passed; `evidence/pytest.txt` |
| Bandit and pip-audit output saved | PENDING TEAM | Full Part B scans have not been performed for Step 11. A focused Bandit check of the new analysis tool passes; this is not a substitute for Part B. |
| Every Part C row has a screenshot or saved output | PENDING TEAM | Capture checklist in `evidence/README.md`; Wireshark, DB Browser and ZAP evidence is not fabricated or claimed. |
| Analysis tool runs on a cover/stego pair and produces artifacts | PASS | Two real encrypted PNG experiments; low-fill outputs in `evidence/`, high-fill outputs in `evidence/high-fill/`. |

Overall Step 11 acceptance remains pending until the team's Parts B/C evidence
and finding dispositions are saved.

## Part A coverage

All server tests use Flask test clients, temporary/in-memory SQLite databases,
test session secrets, and synthetic accounts. Existing tests remain the primary
regressions; Step 11 adds missing coverage rather than duplicating them.

| Requirement | Tests |
| --- | --- |
| Valid registration, lowercase uniqueness, short-password rejection, Argon2id storage and verification | `test_step11.py::test_registration_stores_only_verifiable_argon2id`; `test_step6.py::test_account_regressions_and_cookie_flags` |
| Login success/failure, generic unknown/wrong error, five-failure lockout | `test_step6.py::test_account_regressions_and_cookie_flags`; `test_step8.py::test_lockout_full_fifteen_minutes_and_no_extension` |
| Chat and every defined API operation require login; unknown key lookup 404 | `test_step6.py::test_account_regressions_and_cookie_flags`; `test_step11.py::test_all_api_operations_require_login_even_with_valid_csrf`; `test_unknown_key_lookup_returns_404` |
| Valid JWK, rejection of private `d`/wrong curve, duplicate POST 409 | `test_step6.py::test_public_key_lifecycle`; `test_reject_private_or_malformed_public_keys` |
| POST/PUT CSRF enforcement | `test_step8.py::test_fetch_csrf_enforced`; `test_step11.py::test_html_post_forms_require_csrf` |
| Pending creation, recipient-only ACK deletion, expiry, 101st refusal | `test_step7.py::test_offline_delivery_stored_then_acknowledged`; `test_ack_ownership_and_unknown_id_indistinguishable`; `test_tiny_fractional_ttl_uses_server_creation_time`; `test_queue_cap_101st_and_recipient_pair_independence` |
| Oversized text/stego envelopes rejected | `test_step6.py::test_exact_envelope_size_boundary`; `test_step10.py::test_exact_decoded_png_limit_and_no_pixel_processing` |
| Forbidden plaintext/message-text/private-key column names in all database tables | `test_step11.py::test_every_database_table_excludes_plaintext_and_private_key_columns` inspects the actual temporary database schema. |
| Sixth login/minute returns 429 | `test_step8.py::test_sixth_login_limited_even_with_changed_username` |
| Failed-login audit event without submitted password | `test_step8.py::test_audit_events_without_secret_or_content` |

## Part D implementation and validation

`tools/stego_analysis.py` uses the separately pinned Pillow and NumPy packages
in `requirements-analysis.txt`. It requires single-frame PNGs with equal
dimensions and bounds each side to 4096 pixels. It analyzes RGB only, explicitly
ignoring alpha. Inputs cannot be overwritten by generated artifacts.

It prints size, changed RGB channel count/percentage and both pairs-of-values
statistics. It saves `diff.png`, `original_lsb.png`, `stego_lsb.png` and a
machine-readable `report.json`. LSB planes are binary grayscale R/G/B panels,
not a colored composite. The formula sums only the even member's contribution
and skips empty pairs, exactly as specified. No p-value or detection threshold
is invented.

Analysis tests independently check a hand-calculated histogram, zero changes,
one changed channel, exact diff/LSB pixels, default CLI paths, input preservation
and rejection of mismatched, corrupt and non-PNG inputs without artifacts.

The optional `STEGO_ANALYSIS_DIR` browser hook makes a controlled synthetic
gradient, then uses the existing `encryptStego` implementation with disposable
Web Crypto identities and fresh ephemeral keys. It verifies each signature and
decrypts each PNG back to the synthetic message. Only PNGs and nonsensitive
measurements leave the browser. The experiment uses LSB replacement, without
introducing another crypto or stego implementation.

The two experiments use 0.537109% and 50% capacity, including framing/IV/tag.
The original statistic is 98304; low fill yields 97241.697539 and high fill
24743.683118. The approximately 1.08% versus 74.83% reductions demonstrate the
intended contrast on this deliberately even-valued synthetic cover. The header
and evidence notes explain why this does not establish reliable detection or
universal stealth on natural photographs or with LSB matching.

## Verification

- Full pytest suite: **96 passed**.
- Node position-stream/capacity suite: **5 passed**.
- Real Chrome HTTPS/WSS browser suite with synthetic experiment export:
  **71 passed, 0 failed** (68 existing checks and 3 experiment checks).
- Focused Bandit scan of `tools/stego_analysis.py`: passed.
- `pip check`, browser harness syntax and Git whitespace checks: passed.

Saved measurements, reproduction commands and the remaining team capture
checklist are in [evidence/README.md](../evidence/README.md).

## Files changed

`tools/stego_analysis.py`, `requirements-analysis.txt`, `tests/test_step11.py`,
`tests/test_stego_analysis.py`, `tests/browser_step6.mjs`, `README.md`, this
checks file, and the synthetic images/reports/manifests under `evidence/`.
