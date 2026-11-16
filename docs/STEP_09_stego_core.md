# Step 9: Steganography Core (Standalone Library and Lab Page)

**Goal:** a browser library that hides and extracts bytes in a PNG at key-derived pseudo-random positions, plus a lab page to test it. It is not connected to chat yet.
**Depends on:** Step 8.
**Read first:** [PROJECT_MAIN.md](./PROJECT_MAIN.md) sections 7, 8, 14.

## Create or modify

`static/js/stego.js`, `templates/stego_lab.html`, `static/js/stego_lab.js`, `app.py` (route `/stego-lab`, enabled only when `STEGO_LAB=1` and the user is logged in).

## Design

- Channels: only the R, G, B values of each pixel. `N = width * height * 3`. Channel `c` maps to the RGBA array index `floor(c / 3) * 4 + (c % 3)`. The alpha channel is never touched.
- Frame written into the image: `[length: 4 bytes, big-endian][payload bytes]`, bits written most significant bit first.
- Each payload bit replaces the least significant bit of the channel at the next position from a keyed position stream.

## Tasks

1. **`PositionStream(keyBytes, N)`** producing unique positions in `[0, N)`:
   - Random words come from HMAC-SHA256 (Web Crypto) in counter mode: block `i` = `HMAC(key, 4-byte big-endian i)`, giving 32 bytes = eight 32-bit big-endian words.
   - `randBelow(m)`: draw a word `r`; reject it if `r >= 2^32 - (2^32 % m)`; otherwise return `r % m` (no modulo bias).
   - Lazy Fisher-Yates using a `Map` for swaps. For step `k`: `j = k + randBelow(N - k)`; `vj = swaps.get(j) ?? j`; `vk = swaps.get(k) ?? k`; `swaps.set(j, vk)`; return `vj`. No position ever repeats, and the sequence for a key is always the same, however many positions are read.
2. **`loadImage(blob)`**: confirm PNG by its magic bytes (not just the MIME type); decode with `createImageBitmap(blob, {colorSpaceConversion:"none", premultiplyAlpha:"none"})`; draw to a canvas; `getImageData`. Reject if any pixel has alpha below 255, if the image is smaller than 256x256 or larger than 4096x4096.
3. **`capacityBits(w, h)`** and a usage check: **refuse** to embed above 50% of capacity, and return a warning flag above 10%.
4. **`embed(blob, payloadBytes, keyBytes, {mode})`**: write the frame at stream positions; `mode` is `"replace"` (default) or `"matching"` (when the bit differs, randomly add or subtract 1 using `crypto.getRandomValues`, staying within 0 to 255). Export with `canvas.toBlob("image/png")`. Return `{blob, usedFraction, changedChannels}`.
5. **`extract(blob, keyBytes)`**: read the first 32 stream positions to get the length; sanity-check it (length must fit inside capacity and be at most 50% of it, otherwise throw "no message or wrong key"); read the payload bits; return the bytes.
6. **Lab page** (`/stego-lab`): choose a PNG, type text and a hex key, press Embed, download the result, then Extract from a chosen file with a chosen key. Show used capacity percentage and the number of changed channels. All output through `textContent`.
7. **In-browser self-test** (a button on the lab page): same key gives the same first 1000 positions; the first 100,000 positions have no duplicates; a different key gives a different sequence; payload too large is refused; a JPEG input is refused; an image with transparency is refused; round trip returns the exact bytes; a wrong key throws or returns garbage but never crashes the page.

## Must not do

- Do not use `Math.random` (or any seeded non-cryptographic generator) for positions.
- Do not use a timestamp or any public value as the key.
- Do not send the image or key to the server in this step.
- Do not enable the lab route unless `STEGO_LAB=1`.

## Acceptance checks

- [ ] Embed then Extract with the same key returns the original text exactly.
- [ ] Extract with a different key fails cleanly.
- [ ] The self-test page reports all cases as passing.
- [ ] Opening the stego image next to the original shows no visible difference.
- [ ] Converting the stego image to JPEG and extracting fails.
- [ ] `/stego-lab` returns 404 when `STEGO_LAB` is not `1`.

## Security checklist

- [ ] No private data leaves the browser.
- [ ] The position stream depends only on the key.

## Commit

`step 9: steganography core library and lab`

## Prompt for the AI tool

```
Read docs/PROJECT_MAIN.md completely, then read docs/STEP_09_stego_core.md.
Implement ONLY Step 9. Follow the position-stream algorithm in the step file exactly.
First reply with a short plan listing the files you will create or change. Wait for
my approval before editing. After implementing, run the acceptance checks and report
each one as pass or fail. Do not start Step 10.
```
