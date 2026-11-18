# Step 9: standalone steganography acceptance results

Implemented against PROJECT_MAIN.md and STEP_09_stego_core.md. Chat integration remains outside this step.

## Acceptance checks

| Required check | Result | Evidence |
| --- | --- | --- |
| Embed/extract with the same key returns the exact original text | PASS | Actual Chrome lab UI embeds UTF-8 and script-like text, downloads the real PNG, selects the downloaded file, and extracts identical text through textContent. Binary byte round trips pass in both embedding modes in the on-page self-test. |
| Different key fails cleanly | PASS | Chrome UI handles the different-key extraction without stale output or a page crash. The self-test accepts either the specified framing rejection or different raw bytes. Raw frames do not authenticate keys, so rejection for every possible wrong key is not claimed. |
| Self-test page reports all cases passing | PASS | All eleven cases pass: same-key first 1000 positions; 100000 unique positions; different-key sequence; oversized payload; JPEG with misleading MIME; transparency; replacement and matching byte round trips; wrong key; alpha/RGB bounds; JPEG conversion. |
| Original and stego images have no visible difference | PASS | Inspected a full-page Chrome screenshot with both previews side by side. Browser pixel comparison confirms every channel differs by at most one level and alpha is unchanged; changed-channel metrics match decoded pixel changes in self-test. |
| JPEG conversion fails extraction | PASS | On-page self-test converts an actual stego canvas to JPEG and confirms rejection. Magic-byte validation also rejects JPEG relabeled with PNG MIME. |
| Lab URL returns 404 unless enabled | PASS | Server tests check the disabled route for both anonymous and logged-in requests. Enabled anonymous requests redirect to login; authenticated requests load the CSP-protected lab. |

## Algorithm and limits

`PositionStream(keyBytes, N)` imports a snapshot of the secret as a nonextractable HMAC-SHA256 key. Counter blocks start at zero, with a four-byte big-endian counter and eight big-endian unsigned words per digest. Rejection sampling uses the exact 2^32 threshold, followed by the specified Map-based lazy Fisher-Yates swaps. The sequence depends on the key and carrier capacity, with no timestamp or external random seed. Concurrent next() calls are serialized to retain uniqueness.

The independent Node reference uses native HMAC and a full shuffle array to verify the lazy implementation through an entire 2048-position permutation. It also checks deterministic prefixes after source-key mutation, rejection-sampling behavior, exhaustion, and usage boundaries. Cryptographic operations in production browser code use Web Crypto only.

PNG signature and IHDR dimensions are checked before image decoding. Decoding uses createImageBitmap with colorSpaceConversion/premultiplyAlpha both set to none, followed by Canvas image data and an opacity check. Dimension limits are inclusive at 256 and 4096 per side. Only RGB channels are mapped into the position stream.

The frame is exactly four big-endian length bytes followed by raw payload bytes, written most-significant bit first. Capacity is width × height × 3 bits. The length header counts toward usage: exactly 50% is allowed, anything above is refused, and the warning flag starts strictly above 10%. Extraction validates the decoded length before allocating/reading its payload. Invalid embedded lengths throw `no message or wrong key`.

Replacement changes the LSB directly. Matching changes mismatches by CSPRNG-selected ±1, with forced inward movement at 0/255. Output uses canvas.toBlob with image/png, and includes blob, usedFraction, changedChannels and the warning boolean. The lab UI expects a 32-byte key encoded as 64 hex characters, consistent with the specified 256-bit derived stego key; PositionStream itself accepts nonempty key-byte input.

## Validation

- `node --test tests/test_stego.mjs`: **5 passed**.
- `venv/Scripts/python.exe -m pytest -q -p no:cacheprovider`: **64 passed**, including route flag/authentication coverage and earlier regressions.
- `node tests/browser_step6.mjs`: **54 passed, 0 failed**, including eleven on-page stego self-test cases within one browser assertion.
- JavaScript syntax, Bandit scan, dependency consistency, and Git whitespace checks: passed.

The browser suite keeps the strict CSP unchanged. Its first download inspection attempt was correctly blocked because fetch of blob URLs is outside connect-src. The test now uses Chrome's actual download flow, then selects the downloaded PNG; production code never fetches blob URLs or uploads images. Network inspection confirms no lab POST/PUT, image/text/key upload, or new socket connection. The disabled-by-default flag remains unchanged in the user's environment. Testing uses an isolated in-memory app and temporary files/accounts.

## Changed files

Application: app.py, static/js/stego.js, static/js/stego_lab.js, templates/stego_lab.html, templates/base.html and static/css/style.css.

Validation/documentation: tests/test_stego.mjs, tests/test_step9.py, tests/browser_step6.mjs, README.md and this results file.

No dependencies were added, no private identity keys or chat messages are exported, and no message-envelope or database contract changed. No Step 10 behavior was implemented.
