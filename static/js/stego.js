/** Step 9: opaque PNG steganography. All cryptographic work uses Web Crypto. */
const PNG_MAGIC = [137, 80, 78, 71, 13, 10, 26, 10];
const WORD_RANGE = 2 ** 32;

function bytes(value, name) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array`);
  return value;
}

export class PositionStream {
  constructor(keyBytes, N) {
    bytes(keyBytes, "Key");
    if (!keyBytes.length) throw new Error("A secret key is required");
    if (!Number.isSafeInteger(N) || N < 1 || N > WORD_RANGE) throw new Error("Invalid position count");
    this.N = N;
    this.k = 0;
    this.swaps = new Map();
    this.counter = 0;
    this.words = null;
    this.wordIndex = 8;
    this.pending = Promise.resolve();
    // SECURITY: snapshot the key and import it nonextractably for HMAC only.
    this.key = crypto.subtle.importKey("raw", keyBytes.slice(),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  }

  async word() {
    if (this.wordIndex === 8) {
      if (this.counter >= WORD_RANGE) throw new Error("Position counter exhausted");
      const counter = new Uint8Array(4);
      new DataView(counter.buffer).setUint32(0, this.counter++, false);
      this.words = new DataView(await crypto.subtle.sign("HMAC", await this.key, counter));
      this.wordIndex = 0;
    }
    return this.words.getUint32(4 * this.wordIndex++, false);
  }

  async randBelow(m) {
    if (!Number.isSafeInteger(m) || m < 1 || m > WORD_RANGE) throw new Error("Invalid random bound");
    // SECURITY: rejection sampling avoids modulo bias, including for m=2^32.
    const limit = WORD_RANGE - (WORD_RANGE % m);
    let r;
    do { r = await this.word(); } while (r >= limit);
    return r % m;
  }

  next() {
    // Serialize concurrent consumers as well as ordinary sequential reads.
    const result = this.pending.then(async () => {
      if (this.k >= this.N) throw new Error("Position stream exhausted");
      const k = this.k;
      const j = k + await this.randBelow(this.N - k);
      const vj = this.swaps.get(j) ?? j;
      const vk = this.swaps.get(k) ?? k;
      this.swaps.set(j, vk);
      this.k++;
      return vj;
    });
    this.pending = result.catch(() => {});
    return result;
  }
}

export function capacityBits(width, height) {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1
    || !Number.isSafeInteger(width * height * 3) || width * height * 3 > WORD_RANGE) {
    throw new Error("Invalid image dimensions");
  }
  return width * height * 3;
}

export function usage(payloadLength, width, height) {
  if (!Number.isSafeInteger(payloadLength) || payloadLength < 0 || payloadLength >= WORD_RANGE) {
    throw new Error("Invalid payload length");
  }
  const usedFraction = (payloadLength + 4) * 8 / capacityBits(width, height);
  if (usedFraction > 0.5) throw new Error("Payload exceeds 50% of image capacity");
  return { usedFraction, warning: usedFraction > 0.1 };
}

function imageSize(width, height) {
  if (width < 256 || height < 256 || width > 4096 || height > 4096) {
    throw new Error("PNG dimensions must be between 256 and 4096 pixels on each side");
  }
}

export async function loadImage(blob) {
  if (!(blob instanceof Blob)) throw new TypeError("Choose a PNG file");
  // SECURITY: inspect the signature and dimensions before decoding; MIME labels
  // are untrusted, and excessive image dimensions must not allocate a canvas.
  const header = new Uint8Array(await blob.slice(0, 33).arrayBuffer());
  if (header.length < 33 || !PNG_MAGIC.every((byte, i) => header[i] === byte)
    || new DataView(header.buffer).getUint32(8, false) !== 13
    || String.fromCharCode(...header.slice(12, 16)) !== "IHDR") {
    throw new Error("Only PNG files are supported");
  }
  const view = new DataView(header.buffer);
  imageSize(view.getUint32(16, false), view.getUint32(20, false));
  let bitmap;
  try {
    bitmap = await createImageBitmap(blob, { colorSpaceConversion: "none", premultiplyAlpha: "none" });
  } catch {
    throw new Error("PNG could not be decoded");
  }
  try {
    imageSize(bitmap.width, bitmap.height);
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("Canvas is unavailable");
    context.drawImage(bitmap, 0, 0);
    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    for (let i = 3; i < imageData.data.length; i += 4) {
      if (imageData.data[i] !== 255) throw new Error("PNG must be fully opaque; transparency is not supported");
    }
    return { canvas, context, imageData, width: canvas.width, height: canvas.height };
  } finally {
    bitmap.close();
  }
}

const rgbaIndex = (channel) => Math.floor(channel / 3) * 4 + channel % 3;

export function pngBlob(canvas) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("PNG export failed")), "image/png");
  });
}

export async function embed(blob, payloadBytes, keyBytes, { mode = "replace" } = {}) {
  bytes(payloadBytes, "Payload");
  if (mode !== "replace" && mode !== "matching") throw new Error("Choose replace or matching mode");
  const image = await loadImage(blob);
  const metrics = usage(payloadBytes.length, image.width, image.height);
  const frame = new Uint8Array(payloadBytes.length + 4);
  new DataView(frame.buffer).setUint32(0, payloadBytes.length, false);
  frame.set(payloadBytes, 4);
  const positions = new PositionStream(keyBytes, capacityBits(image.width, image.height));
  const pixels = image.imageData.data;
  let changedChannels = 0;
  const random = new Uint8Array(4096);
  let randomIndex = random.length;
  for (const byte of frame) {
    for (let bit = 7; bit >= 0; bit--) {
      const index = rgbaIndex(await positions.next());
      const desired = (byte >>> bit) & 1;
      const original = pixels[index];
      if ((original & 1) === desired) continue;
      if (mode === "replace") pixels[index] = (original & 254) | desired;
      else if (original === 0) pixels[index] = 1;
      else if (original === 255) pixels[index] = 254;
      else {
        // SECURITY: only CSPRNG bits choose the matching direction. Buffering
        // reduces calls without introducing a second random source.
        if (randomIndex === random.length) { crypto.getRandomValues(random); randomIndex = 0; }
        pixels[index] = original + ((random[randomIndex++] & 1) ? 1 : -1);
      }
      changedChannels++;
    }
  }
  image.context.putImageData(image.imageData, 0, 0);
  return { blob: await pngBlob(image.canvas), ...metrics, changedChannels };
}

export async function extract(blob, keyBytes) {
  const image = await loadImage(blob);
  const positions = new PositionStream(keyBytes, capacityBits(image.width, image.height));
  async function readByte() {
    let result = 0;
    for (let bit = 0; bit < 8; bit++) {
      result = (result << 1) | (image.imageData.data[rgbaIndex(await positions.next())] & 1);
    }
    return result;
  }
  const header = new Uint8Array(4);
  for (let i = 0; i < 4; i++) header[i] = await readByte();
  const length = new DataView(header.buffer).getUint32(0, false);
  // SECURITY: validate untrusted embedded lengths before allocating/reading.
  try { usage(length, image.width, image.height); }
  catch { throw new Error("no message or wrong key"); }
  const payload = new Uint8Array(length);
  for (let i = 0; i < length; i++) payload[i] = await readByte();
  return payload;
}

export async function selfTest(onResult = () => {}) {
  const results = [];
  async function test(name, action) {
    try { await action(); results.push({ case: name, passed: true }); }
    catch { results.push({ case: name, passed: false }); }
    onResult(results.at(-1));
  }
  const assert = (condition) => { if (!condition) throw new Error("Self-test failed"); };
  const rejects = async (action) => { let rejected = false; try { await action(); } catch { rejected = true; } assert(rejected); };
  // SECURITY: self-test keys are fresh random secrets, never timestamps.
  const key = crypto.getRandomValues(new Uint8Array(32));
  const other = crypto.getRandomValues(new Uint8Array(32));
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 256;
  const context = canvas.getContext("2d");
  const pixels = context.createImageData(256, 256);
  for (let i = 0; i < pixels.data.length; i += 4) {
    pixels.data[i] = (i / 4 * 17) % 256;
    pixels.data[i + 1] = (i / 4 * 31) % 256;
    pixels.data[i + 2] = (i / 4 * 13) % 256;
    pixels.data[i + 3] = 255;
  }
  context.putImageData(pixels, 0, 0);
  const cover = await pngBlob(canvas);
  const payload = new Uint8Array([0, 255, 128, 42, ...new TextEncoder().encode("PNG round trip ✓")]);
  const N = capacityBits(256, 256);
  await test("Same key gives the same first 1000 positions", async () => {
    const a = new PositionStream(key, N), b = new PositionStream(key, N);
    for (let i = 0; i < 1000; i++) assert(await a.next() === await b.next());
  });
  await test("First 100000 positions have no duplicates", async () => {
    const stream = new PositionStream(key, N), seen = new Set();
    for (let i = 0; i < 100000; i++) seen.add(await stream.next());
    assert(seen.size === 100000);
  });
  await test("Different keys give different sequences", async () => {
    const a = new PositionStream(key, N), b = new PositionStream(other, N);
    let different = false;
    for (let i = 0; i < 1000; i++) if (await a.next() !== await b.next()) different = true;
    assert(different);
  });
  await test("Payload above 50% is refused", () => rejects(() => embed(cover, new Uint8Array(N / 16 - 3), key)));
  const jpeg = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg"));
  await test("JPEG input is refused even with a PNG MIME label", () => rejects(() => loadImage(new Blob([jpeg], { type: "image/png" }))));
  const alphaPixels = context.getImageData(0, 0, 256, 256);
  alphaPixels.data[3] = 254;
  context.putImageData(alphaPixels, 0, 0);
  await test("Transparency is refused", async () => {
    const transparent = await pngBlob(canvas);
    await rejects(() => loadImage(transparent));
  });
  const encoded = await embed(cover, payload, key);
  await test("Replacement round trip returns exact bytes", async () => {
    const decoded = await extract(encoded.blob, key);
    assert(decoded.length === payload.length && decoded.every((v, i) => v === payload[i]));
  });
  await test("Matching round trip returns exact bytes", async () => {
    const matched = await embed(cover, payload, key, { mode: "matching" });
    const decoded = await extract(matched.blob, key);
    assert(decoded.length === payload.length && decoded.every((v, i) => v === payload[i]));
  });
  await test("Wrong key fails cleanly or produces different bytes", async () => {
    try {
      const decoded = await extract(encoded.blob, other);
      assert(decoded.length !== payload.length || decoded.some((v, i) => v !== payload[i]));
    } catch (error) { assert(error.message === "no message or wrong key"); }
  });
  await test("Only RGB LSBs change and alpha stays opaque", async () => {
    const original = (await loadImage(cover)).imageData.data;
    const changed = (await loadImage(encoded.blob)).imageData.data;
    let count = 0;
    for (let i = 0; i < changed.length; i++) {
      if (i % 4 === 3) assert(changed[i] === original[i]);
      else { assert((changed[i] & 254) === (original[i] & 254)); if (changed[i] !== original[i]) count++; }
    }
    assert(count === encoded.changedChannels);
  });
  await test("JPEG conversion destroys the supported PNG carrier", async () => {
    const image = await loadImage(encoded.blob);
    const converted = await new Promise((resolve) => image.canvas.toBlob(resolve, "image/jpeg"));
    await rejects(() => extract(converted, key));
  });
  return results;
}
