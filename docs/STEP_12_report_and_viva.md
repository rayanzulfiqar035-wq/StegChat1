# Step 12: Documentation, Threat Model and Viva Preparation

**Goal:** a README anyone can follow, a threat model that matches what was really built, a demo script, and answers for the viva.
**Depends on:** Step 11.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) (all sections), then read the actual code.

## Rule for this step

Document **only what is really implemented.** Read the code before writing each claim. Anything not built goes under "Future work", never into the description of the system.

## Create

`README.md`, `THREAT_MODEL.md`, `DEMO_SCRIPT.md`, `VIVA_QA.md` (in the project root or `docs/`).

## Tasks

1. **`README.md`**: what the app is; requirements; setup (virtual environment, `pip install`, mkcert commands, `.env` from `.env.example`); how to run; how to run the tests; folder overview; a screenshot or two. A teammate must be able to run the project on a fresh computer using only this file.
2. **`THREAT_MODEL.md`**:
   - Assets: message content, private keys, passwords, metadata.
   - Attackers: network eavesdropper, curious or compromised server, another user, someone who steals the database file, a malicious page script (XSS).
   - A table using the six STRIDE categories: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege, each with the threat in this app, the defence that is actually implemented, and where in the code it lives.
   - Trust assumptions (for example: the browser and operating system are not compromised; users compare fingerprints).
   - **Limitations**, stated honestly: the server could substitute public keys unless users compare fingerprints; partial forward secrecy only (the recipient's long-term private key can decrypt any captured message sent to it); the server sees metadata (who, when, size); a user who clears browser data loses their keys; an XSS bug would expose decrypted messages; steganography can be detected by statistical analysis and is destroyed by image recompression; no group chat; no message history.
   - Future work: Double Ratchet style forward secrecy, one-time prekeys, key backup protected by a passphrase, safety-number verification by QR code.
3. **`DEMO_SCRIPT.md`**: a numbered script for a live demonstration with expected result at each step: register two users; show hashed passwords in the DB; exchange fingerprints; send a message while the recipient is offline; show ciphertext in the database and in DevTools frames; recipient logs in, reads it, row disappears; show Wireshark TLS capture; attempt XSS, SQL injection and brute force; tamper with a ciphertext; show stego before and after, difference image and analysis output; show failed extraction with a wrong key and after JPEG conversion.
4. **`VIVA_QA.md`**: at least 25 likely questions with short answers drawn from this project, covering: what E2EE is and the alternatives (no encryption, TLS only, server-side encryption); why ephemeral keys; why HKDF and labels; why AES-GCM and what the tag does; why a signature is needed and what it prevents; why Argon2 instead of SHA-256; what TOFU is and the key substitution attack; what the CSP, CSRF token and rate limiter each stop; why the server deletes only on acknowledgement; how WhatsApp and email encryption differ from this design; how the stego positions are derived without sending a seed and why a timestamp would be unsafe; how stego is detected; what you would improve.
5. Add a short "Where each security feature lives" table (feature, file, function) so the team can find any answer quickly.

## Must not do

- Do not claim features that are not in the code.
- Do not copy the manual's text blindly; verify each statement against the project.

## Acceptance checks

- [ ] A teammate runs the project from the README on a clean setup without help.
- [ ] Every defence listed in the threat model can be found in the code at the stated location.
- [ ] The demo script runs from start to finish without improvisation.
- [ ] Each team member can answer at least ten questions from `VIVA_QA.md` without reading.

## Commit

`step 12: documentation and threat model`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_12_report_and_viva.md.
Read the actual project code before writing any claim. Implement ONLY Step 12.
First reply with a short plan listing the files you will create. Wait for my approval
before editing. When done, list every statement you could not verify in the code.
```
