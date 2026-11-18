/** Independent algorithm and boundary checks; run with node --test. */
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { PositionStream, capacityBits, usage } from "../static/js/stego.js";

const key = Uint8Array.from({ length: 32 }, (_, i) => i);

test("HMAC counter, word endianness and lazy swaps match an independent full shuffle", async () => {
  const N = 2048, indices = Array.from({ length: N }, (_, i) => i);
  let block = Buffer.alloc(0), offset = 32, counter = 0;
  function word() {
    if (offset === 32) {
      const input = Buffer.alloc(4); input.writeUInt32BE(counter++);
      block = createHmac("sha256", key).update(input).digest(); offset = 0;
    }
    const value = block.readUInt32BE(offset); offset += 4; return value;
  }
  const expected = [];
  for (let k = 0; k < N; k++) {
    const m = N - k, limit = 2 ** 32 - (2 ** 32 % m);
    let r; do { r = word(); } while (r >= limit);
    const j = k + r % m;
    [indices[k], indices[j]] = [indices[j], indices[k]];
    expected.push(indices[k]);
  }
  const stream = new PositionStream(key, N);
  const actual = await Promise.all(Array.from({ length: N }, () => stream.next()));
  assert.deepEqual(actual, expected);
  assert.equal(new Set(actual).size, N);
  await assert.rejects(stream.next(), /exhausted/);
});

test("rejection sampling discards words beyond the unbiased limit", async () => {
  const stream = new PositionStream(key, 10);
  const words = [0xffffffff, 0xfffffffe, 17];
  stream.word = async () => words.shift();
  assert.equal(await stream.randBelow(10), 7);
  assert.equal(words.length, 0);
});

test("stream snapshots keys and prefixes stay deterministic", async () => {
  const mutable = key.slice(), first = new PositionStream(mutable, 10000);
  mutable.fill(99);
  const second = new PositionStream(key, 10000), other = new PositionStream(mutable, 10000);
  let differs = false;
  for (let i = 0; i < 1000; i++) {
    const position = await first.next();
    assert.equal(position, await second.next());
    if (position !== await other.next()) differs = true;
  }
  assert(differs);
});

test("capacity includes header, exact 50% is allowed, warning starts strictly above 10%", () => {
  assert.equal(capacityBits(256, 256), 196608);
  assert.equal(usage(12284, 256, 256).usedFraction, 0.5);
  assert.throws(() => usage(12285, 256, 256), /50%/);
  assert.equal(usage(5996, 400, 400).warning, false);
  assert.equal(usage(5997, 400, 400).warning, true);
});

test("invalid stream and capacity arguments fail without allocating large buffers", async () => {
  for (const n of [0, -1, 1.5, Infinity, 2 ** 32 + 1]) assert.throws(() => new PositionStream(key, n));
  assert.throws(() => new PositionStream(new Uint8Array(), 1));
  assert.throws(() => capacityBits(-1, 256));
  assert.throws(() => usage(-1, 256, 256));
  const stream = new PositionStream(key, 1);
  assert.equal(await stream.next(), 0);
  await assert.rejects(stream.next(), /exhausted/);
});
