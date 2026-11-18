# Step 11 evidence

Only synthetic test data is committed here. No real accounts, private keys,
password hashes, session cookies, audit logs or captured user conversations.
The encrypted PNGs use disposable identities generated inside the isolated
browser test. Those private keys are never exported or saved.

## Automated evidence (Parts A and D)

- `pytest.txt`: complete Python test suite result.
- `browser.txt`: isolated HTTPS/WSS Chrome checks, including signature checks
  and decryption of both analysis experiments. The lab screenshot mentioned in
  this output stays in a temporary directory and is **not** committed: it shows
  a disposable lab key.
- `synthetic/cover.png`: 256 x 256 deliberately even-valued RGB gradient.
- `synthetic/low_fill.png` and `synthetic/high_fill.png`: actual encrypted
  carriers generated with the existing browser `encryptStego` implementation.
- `synthetic/manifest.json`: payload sizes, capacity fractions, changed-channel
  counts, and successful signature/decryption checks. Contains no keys.
- `analysis-low.txt`, `report.json`, `diff.png`, `original_lsb.png`,
  `stego_lsb.png`: default-output low-fill analysis.
- `analysis-high.txt` and `high-fill/`: high-fill analysis and the same artifacts.

The diff stores 255 in each changed RGB channel and 0 in unchanged channels.
Each LSB image is a grayscale triptych: R, G, B planes, left to right.

| Experiment | UTF-8 message bytes | Framed bytes | RGB capacity used | Channels changed | Cover statistic | Stego statistic |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Low fill | 100 | 132 | 0.537109% | 533 (0.271098%) | 98304 | 97241.697539 |
| High fill | 12256 | 12288 | 50% | 49033 (24.939473%) | 98304 | 24743.683118 |

Framing includes the 4-byte length, 12-byte IV and 16-byte GCM tag. Capacity
usage counts embedded bits; changed channels count only bits that needed a
change. They are different measurements.

The low-fill statistic decreases about 1.08%; high fill decreases about 74.83%.
This is a controlled demonstration with a deliberately biased cover, not a
representative photograph or a calibrated detection threshold. Natural images,
low fill and LSB matching may behave differently. Low fill is not proof that
hidden data cannot be detected. Reusing this cover is solely for a controlled
comparison with fresh ephemeral keys; normal messaging should use each cover
once.

## Reproduce

From the repository root with the virtual environment active:

```powershell
python -m pip install -r requirements.txt -r requirements-analysis.txt
python -m pytest -q -p no:cacheprovider
$env:STEGO_ANALYSIS_DIR = Join-Path (Get-Location) 'evidence/synthetic'
node tests/browser_step6.mjs
python tools/stego_analysis.py evidence/synthetic/cover.png evidence/synthetic/low_fill.png
python tools/stego_analysis.py evidence/synthetic/cover.png evidence/synthetic/high_fill.png --output-dir evidence/high-fill
```

Browser prerequisites and trusted local TLS setup are in the project README.
The browser suite uses its own in-memory database on port 5443. It does not use
the regular application's database. Results vary between runs because each
encryption uses fresh randomness. Regenerating the PNGs requires rerunning both
analyses and updating the measured table.

## Pending team evidence (Parts B and C)

These items are **not completed** by the AI-only Parts A/D implementation. The
automated checks above supplement the team's captures; they do not stand in for
a Wireshark recording, DB Browser capture or ZAP report.

| Required capture | Suggested saved file | Status |
| --- | --- | --- |
| Full application Bandit scan | `bandit.txt` | Pending team run |
| Dependency vulnerability audit | `pip-audit.txt` | Pending team run |
| DevTools Network/WS encrypted envelopes | `devtools-wss.png` | Pending team capture |
| DB Browser hashes/public keys and pending queue before/after delivery | `database-before.png`, `database-after.png` | Pending team capture |
| Wireshark loopback TLS on port 5000 | `wireshark-tls.png` | Pending team capture |
| ZAP baseline against the local HTTPS application | `zap-report.html` | Pending team run and finding review |
| XSS, SQL injection, brute-force 429 and tampered-byte rejection | `attacks.txt` and/or screenshots | Pending team capture |

With the virtual environment active, the prescribed Part B commands are:

```powershell
python -m bandit -r . -x ./venv,./tests
python -m pip_audit
```

Save their output and record dispositions for findings. For manual captures use
disposable local accounts and synthetic messages. Exclude cookies, CSRF values,
password values, private keys and unrelated traffic. Restrict scanners to your
own local app. Inspect files before committing them; do not copy the real
database or raw application logs into this folder.
