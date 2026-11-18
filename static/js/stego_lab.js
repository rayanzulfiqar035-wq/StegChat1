/** Local-only lab controls: no network, persistent storage or uploads. */
import { loadImage, capacityBits, usage, embed, extract, selfTest } from "./stego.js";

const element = (id) => document.getElementById(id);
const encoder = new TextEncoder();
const urls = new Map();
let coverSize = null;
let previewRequest = 0;

function status(message, error = false) {
  element("lab-status").textContent = message;
  element("lab-status").className = error ? "field-error" : "";
}
function keyBytes() {
  const hex = element("stego-key").value.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("Enter a 64-character hexadecimal key, or generate a random key.");
  return new Uint8Array(hex.match(/../g).map((pair) => parseInt(pair, 16)));
}
function setImage(id, blob) {
  if (urls.has(id)) URL.revokeObjectURL(urls.get(id));
  const url = URL.createObjectURL(blob);
  urls.set(id, url);
  element(id).src = url;
  element(id).classList.remove("is-hidden");
  return url;
}
function clearResult() {
  element("download-stego").classList.add("is-hidden");
  element("download-stego").removeAttribute("href");
  element("stego-preview").classList.add("is-hidden");
  element("stego-preview").removeAttribute("src");
  if (urls.has("stego-preview")) URL.revokeObjectURL(urls.get("stego-preview"));
  urls.delete("stego-preview");
  element("embed-metrics").textContent = "";
}
function updateUsage() {
  element("capacity-warning").textContent = "";
  if (!coverSize) return;
  const { width, height } = coverSize;
  const size = encoder.encode(element("payload-text").value).length;
  const fraction = (size + 4) * 8 / capacityBits(width, height);
  element("capacity-info").textContent = `${width} × ${height}; ${size} payload bytes; ${(fraction * 100).toFixed(2)}% of RGB bit capacity including the length header.`;
  try {
    if (usage(size, width, height).warning) element("capacity-warning").textContent = "Above 10% capacity: changes may be easier to detect.";
  } catch {
    element("capacity-warning").textContent = "Above 50% capacity: choose less text or a larger PNG.";
  }
}
async function run(action) {
  const controls = [...document.querySelectorAll(".stego-lab button, .stego-lab input, .stego-lab textarea, .stego-lab select")];
  controls.forEach((control) => { control.disabled = true; });
  status("Working locally...");
  try { await action(); }
  catch (error) { status(error.message || "The operation could not be completed.", true); }
  finally { controls.forEach((control) => { control.disabled = false; }); }
}
element("generate-key").addEventListener("click", () => {
  // SECURITY: no timestamps, public seeds or noncryptographic random source.
  const key = crypto.getRandomValues(new Uint8Array(32));
  element("stego-key").value = Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("");
  status("Random key generated. Keep it to extract this image later.");
});
element("cover-file").addEventListener("change", async () => {
  const request = ++previewRequest;
  coverSize = null;
  clearResult();
  element("cover-preview").classList.add("is-hidden");
  element("capacity-info").textContent = "Choose a PNG to see capacity.";
  element("capacity-warning").textContent = "";
  const file = element("cover-file").files[0];
  if (!file) return;
  try {
    const image = await loadImage(file);
    if (request !== previewRequest) return;
    coverSize = { width: image.width, height: image.height };
    setImage("cover-preview", file);
    updateUsage();
    status("PNG ready. Enter text and a key, then embed.");
  } catch (error) { if (request === previewRequest) status(error.message, true); }
});
element("payload-text").addEventListener("input", updateUsage);
element("embed-button").addEventListener("click", () => run(async () => {
  clearResult();
  const file = element("cover-file").files[0];
  if (!file) throw new Error("Choose a cover PNG first.");
  const result = await embed(file, encoder.encode(element("payload-text").value), keyBytes(), { mode: element("embed-mode").value });
  const url = setImage("stego-preview", result.blob);
  element("download-stego").href = url;
  element("download-stego").classList.remove("is-hidden");
  element("embed-metrics").textContent = `Used ${(result.usedFraction * 100).toFixed(2)}% capacity; ${result.changedChannels} RGB channels changed.`;
  element("capacity-warning").textContent = result.warning ? "Above 10% capacity: changes may be easier to detect." : "";
  status("Embedding complete. Download the PNG and keep its secret key.");
}));
element("extract-button").addEventListener("click", () => run(async () => {
  element("extracted-text").textContent = "";
  const file = element("extract-file").files[0];
  if (!file) throw new Error("Choose the PNG to extract first.");
  const payload = await extract(file, keyBytes());
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(payload); }
  catch { throw new Error("Extracted bytes are not valid UTF-8 text; check the key and image."); }
  // SECURITY: extracted text is never parsed as markup or evaluated.
  element("extracted-text").textContent = text;
  status("Extraction complete. This raw frame does not authenticate the key or content.");
}));
element("stego-self-test").addEventListener("click", () => run(async () => {
  element("self-test-results").replaceChildren();
  const results = await selfTest((result) => {
    const item = document.createElement("li");
    item.textContent = `${result.passed ? "PASS" : "FAIL"}: ${result.case}`;
    element("self-test-results").appendChild(item);
  });
  status(`${results.filter((result) => result.passed).length}/${results.length} self-tests passed.`, results.some((result) => !result.passed));
}));
window.addEventListener("pagehide", () => { for (const url of urls.values()) URL.revokeObjectURL(url); });
