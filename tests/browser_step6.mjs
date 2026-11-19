/** Step 6–8 browser acceptance checks using installed Chrome and Node.
 * Starts an isolated in-memory HTTPS app; never opens the user's real database.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import https from "node:https";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.STEP6_TEST_PORT || 5443);
const base = `https://localhost:${port}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let server, browser, ws;
let passed = 0;
const failures = [];
function check(name, condition) {
  console.log(`${condition ? "PASS" : "FAIL"} ${name}`);
  if (condition) passed++;
  else failures.push(name);
}
const py = `import secrets
from app import create_app
from config import Config
from extensions import socketio
from extensions import db
from models import PendingMessage
import base64
from flask import jsonify, render_template_string
from datetime import datetime, timedelta, timezone
from cleanup import delete_expired_messages
class ReviewConfig(Config):
 TESTING=True
 STEGO_LAB=True
 RATELIMIT_ENABLED=False
 SOCKET_RATE_LIMIT_ENABLED=False
 AUDIT_LOG_PATH=__import__('os').environ['STEP_TEST_AUDIT_PATH']
 SECRET_KEY=secrets.token_hex(32)
 SQLALCHEMY_DATABASE_URI='sqlite:///:memory:'
app=create_app(ReviewConfig)
# Inspection hooks exist only in this in-memory test server.
@app.get('/__test/csp-experiment')
def csp_experiment():
 return render_template_string('''<!doctype html><meta name="csrf-token" content="test"><script>window.__inlineExecuted=true;</script><p>CSP experiment</p>''')
@app.get('/__test/pending')
def pending():
 return jsonify([{'id':m.id,'ct':m.ciphertext,'sig':m.signature,'kind':m.kind,'iv':m.iv} for m in PendingMessage.query.all()])
@app.get('/__test/tamper-png/<int:delivery_id>')
def tamper_png(delivery_id):
 m=db.session.get(PendingMessage,delivery_id)
 raw=bytearray(base64.b64decode(m.ciphertext));raw[-1]^=1
 m.ciphertext=base64.b64encode(raw).decode('ascii');db.session.commit()
 return jsonify(ok=True)
@app.get('/__test/expire')
def expire():
 for m in PendingMessage.query.all(): m.created_at=datetime.now(timezone.utc)-timedelta(days=8)
 db.session.commit()
 return jsonify(deleted=delete_expired_messages())
# The isolated fixture uses its own exact origin, leaving port 5000 alone.
socketio.server.eio.cors_allowed_origins=['${base}']
socketio.run(app,host='127.0.0.1',port=${port},ssl_context=(Config.SSL_CERT,Config.SSL_KEY),allow_unsafe_werkzeug=True,debug=False,use_reloader=False)
`;

try {
  const occupied = await new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    socket.on("connect", () => { socket.destroy(); resolve(true); });
    socket.on("error", () => resolve(false));
  });
  assert.equal(occupied, false, "Test port is occupied; choose another STEP6_TEST_PORT");
  const ca = await fs.readFile(path.join(process.env.CAROOT || path.join(os.homedir(), "AppData/Local/mkcert"), "rootCA.pem"));
  const probe = () => new Promise((resolve, reject) => {
    const request = https.get(base + "/login", { ca }, (response) => {
      response.resume(); resolve(response.statusCode);
    });
    request.on("error", reject);
    request.setTimeout(1000, () => request.destroy());
  });
  const auditDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "stegchat-test-audit-"));
  server = spawn(path.join(root, "venv/Scripts/python.exe"), ["-B", "-c", py], {
    cwd: root, windowsHide: true, stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env, STEP_TEST_AUDIT_PATH: path.join(auditDirectory, "audit.log") },
  });
  let serverErrors = "";
  server.stderr.on("data", (data) => { serverErrors += data.toString(); });
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { if (await probe() === 200) { ready = true; break; } } catch { /* starting */ }
    await sleep(100);
  }
  assert(ready, "HTTPS test server failed to start: " + serverErrors.slice(-1500));
  check("HTTPS certificate verifies against the local CA", true);
  const plainServes = await new Promise((resolve) => {
    const request = http.get(`http://127.0.0.1:${port}/`, (response) => {
      response.resume(); resolve(response.statusCode === 200);
    });
    request.on("error", () => resolve(false));
    request.setTimeout(1000, () => { request.destroy(); resolve(false); });
  });
  check("HTTP does not serve the application", !plainServes);
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), "stegchat-step6-"));
  browser = spawn(process.env.CHROME_BIN || "C:/Program Files/Google/Chrome/Application/chrome.exe", [
    "--headless=new", "--disable-gpu", "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1", "--user-data-dir=" + profile,
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
    "--disable-component-update", "--disable-default-apps", "--disable-sync", "about:blank",
  ], { windowsHide: true, stdio: "ignore" });
  browser.on("error", (error) => { console.error(error.message); });
  let debug;
  for (let i = 0; i < 100; i++) {
    try { debug = (await fs.readFile(path.join(profile, "DevToolsActivePort"), "utf8")).trim().split("\n"); break; }
    catch { await sleep(100); }
  }
  assert(debug, "Chrome debugging endpoint unavailable");
  ws = new WebSocket(`ws://127.0.0.1:${debug[0]}${debug[1]}`);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let nextId = 0;
  const pending = new Map(), sessions = new Map();
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.id) {
      const request = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) request?.reject(new Error(message.error.message));
      else request?.resolve(message.result);
    } else {
      const page = sessions.get(message.sessionId);
      if (!page) return;
      if (message.method === "Network.requestWillBeSent") {
        const request = message.params.request;
        page.requests.push({ url: request.url, method: request.method, body: request.postData || "" });
        if (request.url.endsWith("/api/keys")) page.uploads.push(request.method);
      }
      if (message.method === "Network.webSocketCreated") page.urls.push(message.params.url);
      if (message.method === "Network.webSocketFrameSent") page.frames.push(message.params.response.payloadData);
      if (message.method === "Runtime.exceptionThrown") page.errors.push(message.params.exceptionDetails.text);
    }
  };
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
  async function evaluate(page, expression) {
    const result = await call("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, page.id);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  }
  async function wait(page, expression) {
    for (let i = 0; i < 150; i++) {
      try { if (await evaluate(page, expression)) return; } catch { /* navigation */ }
      await sleep(100);
    }
    const state = await evaluate(page, "JSON.stringify({url:location.href,title:document.title,status:document.getElementById('chat-status')?.textContent})");
    throw new Error("Timed out: " + expression + "; " + state);
  }
  async function page(script) {
    const { browserContextId } = await call("Target.createBrowserContext");
    const { targetId } = await call("Target.createTarget", { url: "about:blank", browserContextId });
    const { sessionId } = await call("Target.attachToTarget", { targetId, flatten: true });
    const result = { id: sessionId, context: browserContextId, uploads: [], urls: [], frames: [], errors: [], requests: [] };
    sessions.set(sessionId, result);
    await call("Page.enable", {}, sessionId);
    await call("Network.enable", {}, sessionId);
    await call("Runtime.enable", {}, sessionId);
    await call('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false }, sessionId);
    if (script) await call("Page.addScriptToEvaluateOnNewDocument", { source: script }, sessionId);
    return result;
  }
  async function navigate(page, route) {
    await evaluate(page, "window.__previousDocument = true");
    const result = await call("Page.navigate", { url: base + route }, page.id);
    assert(!result.errorText, result.errorText);
    await wait(page, "!window.__previousDocument && document.readyState === 'complete' && !!document.querySelector('meta[name=\"csrf-token\"]')");
  }
  async function captureUi(name, target) {
    if (!process.env.UI_SCREENSHOT_DIR) return;
    const directory = path.resolve(process.env.UI_SCREENSHOT_DIR);
    await fs.mkdir(directory, { recursive: true });
    await wait(target,"document.readyState==='complete' && document.documentElement.clientWidth>0");
    await evaluate(target,'new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    const { cssContentSize: size } = await call('Page.getLayoutMetrics', {}, target.id);
    const shot = await call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
      clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }, target.id);
    await fs.writeFile(path.join(directory, name + '.png'), Buffer.from(shot.data, 'base64'));
  }
  const uploadProbe = `{
    const original = window.fetch;
    window.fetch = async function(url, options) {
      if (url === '/api/keys' && options?.method === 'POST') {
        const k = await import('/static/js/keystore.js');
        const username = document.getElementById('current-username').textContent.trim();
        window.__storedBeforeUpload = !!(await k.getIdentity(username));
      }
      return original.call(this, url, options);
    };
  }`;
  async function account(page, username) {
    await navigate(page, "/register");
    await evaluate(page, `(async()=>{
      const token=document.querySelector('meta[name="csrf-token"]').content;
      await fetch('/register',{method:'POST',body:new URLSearchParams({username:'${username}',password:'browser-test-password-123',confirm:'browser-test-password-123',csrf_token:token})});
      await fetch('/login',{method:'POST',body:new URLSearchParams({username:'${username}',password:'browser-test-password-123',csrf_token:token})});
    })()`);
    await navigate(page, "/chat");
  }
  const entry = await page();
  await navigate(entry, '/');
  check('website entry opens login with a registration link and local messaging illustration', await evaluate(entry,
    "location.pathname==='/login' && !!document.querySelector('a[href=\"/register\"]') && document.querySelector('.auth-illustration').naturalWidth>0"));
  await captureUi('login-desktop', entry);
  await call('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, entry.id);
  check('login fits a mobile viewport without horizontal overflow', await evaluate(entry,
    'document.documentElement.scrollWidth<=window.innerWidth'));
  await captureUi('login-mobile', entry);
  const alice = await page(uploadProbe), bob = await page(uploadProbe);
  await account(alice, "alice"); await account(bob, "bob");
  const identityReady = "window.e2ee?.socket.connected && /^[0-9A-F]{4} /.test(document.getElementById('my-fingerprint').textContent)";
  await wait(alice, identityReady); await wait(bob, identityReady);
  check("two isolated browser sessions load trusted HTTPS with Web Crypto", await evaluate(alice, "isSecureContext && !!crypto.subtle"));
  check('sidebar exposes Chat and Stego with the encrypted-send shortcut', await evaluate(alice,
    "!!document.querySelector('.sidebar a[href=\"/chat\"]') && !!document.querySelector('.sidebar a[href=\"/stego\"]') && !!document.querySelector('.stego-send-link[href=\"/stego\"]')"));
  await captureUi('chat-desktop', alice);
  await evaluate(alice,"document.getElementById('sidebar-toggle').click()");
  check('sidebar collapses with accessible state and remains navigable', await evaluate(alice,
    "document.getElementById('workspace').dataset.sidebarCollapsed==='true' && document.getElementById('sidebar-toggle').getAttribute('aria-expanded')==='false' && document.querySelector('.sidebar a[href=\"/stego\"]').getBoundingClientRect().width>0"));
  await evaluate(alice,"document.getElementById('sidebar-toggle').click()");
  check("connections use WSS", [alice, bob].every((p) => p.urls.some((url) => url.startsWith(`wss://localhost:${port}/`))));
  check("first initialization uploads exactly once per account", [alice, bob].every((p) => p.uploads.filter((m) => m === "POST").length === 1));
  check("private identity committed before public-key upload", await evaluate(alice, "window.__storedBeforeUpload") && await evaluate(bob, "window.__storedBeforeUpload"));
  check("IndexedDB private keys are nonextractable CryptoKeys", await evaluate(alice, `(async()=>{const k=await import('/static/js/keystore.js');const i=await k.getIdentity('alice');return !i.ecdhPrivateKey.extractable&&!i.ecdsaPrivateKey.extractable&&i.ecdhPrivateKey.constructor.name==='CryptoKey';})()`));
  check("all nine browser selfTest cases pass", await evaluate(alice, "(async()=>{const r=await e2ee.selfTest();return r.length===9&&r.every(x=>x.passed);})()"));
  for (const p of [alice, bob]) await evaluate(p, `{
    const emit=e2ee.socket.emit;
    e2ee.socket.emit=function(event,...args){if(event==='send_message')window.__lastEnvelope=args[0];return emit.call(this,event,...args);};
  }`);
  async function select(page, username) {
    await evaluate(page, `{const i=document.getElementById('recipient-input');i.value=${JSON.stringify(username)};i.dispatchEvent(new Event('input'));}`);
    await wait(page, "!document.getElementById('send-btn').disabled");
  }
  async function send(page, text) {
    await evaluate(page, `{document.getElementById('message-input').value=${JSON.stringify(text)};document.getElementById('message-input').dispatchEvent(new Event('input'));document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));}`);
    await wait(page, `document.getElementById('chat-status').textContent==='Message sent' && document.getElementById('message-input').value===''`);
    return evaluate(page, "window.__lastEnvelope");
  }
  const contains = (text) => `Array.from(document.querySelectorAll('.message-item--incoming .message-body')).some(x=>x.textContent===${JSON.stringify(text)})`;
  await evaluate(alice,`{
    document.getElementById('recipient-input').value='bob';document.getElementById('recipient-input').dispatchEvent(new Event('input'));
    document.getElementById('message-input').value='not approved';document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));
  }`);
  check('phonebook blocks sending to a stranger before encryption',await evaluate(alice,
    "document.getElementById('send-btn').disabled && !window.__lastEnvelope && document.getElementById('chat-status').textContent.includes('approved phonebook contact')"));
  await evaluate(alice,`{
    document.getElementById('phonebook-username').value='bob';document.getElementById('phonebook-form').dispatchEvent(new Event('submit',{cancelable:true}));
  }`);
  await wait(bob,"!!document.querySelector('.phonebook-entry[data-username=\"alice\"][data-status=\"incoming\"]')");
  await wait(alice,"!!document.querySelector('.phonebook-entry[data-username=\"bob\"][data-status=\"outgoing\"]')");
  check('phonebook request reaches recipient while messaging remains blocked',await evaluate(alice,
    "!!document.querySelector('.phonebook-entry[data-username=\"bob\"][data-status=\"outgoing\"]') && document.getElementById('send-btn').disabled"));
  await evaluate(bob,"document.querySelector('.phonebook-entry[data-username=\"alice\"] button').click()");
  for(const [target,peer] of [[alice,'bob'],[bob,'alice']])await wait(target,
    `!!document.querySelector('.phonebook-entry[data-username="${peer}"][data-status="accepted"]')`);
  check('recipient acceptance adds both users to their phonebooks',true);
  const keyless = await page();
  await navigate(keyless, '/register');
  await evaluate(keyless, `(async()=>{
    const csrf=document.querySelector('meta[name="csrf-token"]').content;
    await fetch('/register',{method:'POST',body:new URLSearchParams({username:'keyless',password:'browser-test-password-123',confirm:'browser-test-password-123',csrf_token:csrf})});
    await fetch('/login',{method:'POST',body:new URLSearchParams({username:'keyless',password:'browser-test-password-123',csrf_token:csrf})});
  })()`);
  await evaluate(alice,`fetch('/api/contacts',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':document.querySelector('meta[name="csrf-token"]').content},body:JSON.stringify({username:'keyless'})}).then(r=>r.status)`);
  await evaluate(keyless,`fetch('/api/contacts/alice/accept',{method:'POST',headers:{'X-CSRFToken':document.querySelector('meta[name="csrf-token"]').content}}).then(r=>r.status)`);
  await wait(alice,"!!document.querySelector('.phonebook-entry[data-username=\"keyless\"][data-status=\"accepted\"]')");
  await evaluate(alice, "document.getElementById('recipient-input').value='keyless';document.getElementById('recipient-input').dispatchEvent(new Event('input'))");
  await wait(alice, "document.getElementById('chat-status').textContent.includes('has not set up')");
  check('registered contact without keys explains first-login setup and blocks send', await evaluate(alice, "document.getElementById('send-btn').disabled && document.querySelector('#alert-actions button').textContent==='Retry contact lookup'"));
  await evaluate(keyless, `(async()=>{
    const csrf=document.querySelector('meta[name="csrf-token"]').content;
    await fetch('/login',{method:'POST',body:new URLSearchParams({username:'keyless',password:'browser-test-password-123',csrf_token:csrf})});
  })()`);
  await navigate(keyless, '/chat'); await wait(keyless, identityReady);
  await evaluate(alice, "document.querySelector('#alert-actions button').click()");
  await wait(alice, "!document.getElementById('send-btn').disabled");
  check('retry succeeds after contact opens Chat without resetting any identity', await evaluate(alice, "document.getElementById('security-alert').classList.contains('is-hidden')"));
  await evaluate(alice, "document.getElementById('recipient-input').value='not_registered';document.getElementById('recipient-input').dispatchEvent(new Event('input'))");
  await wait(alice, "document.getElementById('chat-status').textContent.includes('approved phonebook contact')");
  check('usernames outside the phonebook cannot be selected for sending', await evaluate(alice, "document.getElementById('send-btn').disabled"));
  for (const [status, explanation] of [[401,'session has expired'],[429,'Wait a minute']]) {
    await evaluate(alice, `{
      window.__lookupFetch=window.fetch;
      window.fetch=function(url,options){if(url==='/api/users/bob/keys')return Promise.resolve(new Response('{}',{status:${status}}));return window.__lookupFetch.call(this,url,options);};
      document.getElementById('recipient-input').value='bob';document.getElementById('recipient-input').dispatchEvent(new Event('input'));
    }`);
    await wait(alice, `document.getElementById('chat-status').textContent.includes(${JSON.stringify(explanation)})`);
    check(`HTTP ${status} lookup failure gets a clear explanation`, await evaluate(alice, "document.getElementById('send-btn').disabled"));
    await evaluate(alice, 'window.fetch=window.__lookupFetch;void 0');
  }
  await select(alice, "bob");
  check("contact trust saved under the same account-scoped lookup key", await evaluate(alice, "(async()=>{const k=await import('/static/js/keystore.js');return !!(await k.getContact('bob','alice'));})()"));
  const text = "<script>alert(1)</script> encrypted browser test";
  const first = await send(alice, text);
  await wait(bob, contains(text));
  check("two browsers exchange readable encrypted messages", true);
  check("script text is harmless in actual DOM", await evaluate(bob, "document.querySelector('.message-body').children.length===0"));
  const second = await send(alice, "fresh ephemeral key test");
  await wait(bob, contains("fresh ephemeral key test"));
  check("new message has distinct eph and IV", first.eph !== second.eph && first.iv !== second.iv);
  const frames = alice.frames.filter((frame) => frame.includes('"send_message"'));
  check("WSS frames contain only ciphertext envelopes, never message text", frames.length >= 2 && frames.every((frame) => !frame.includes(text) && !frame.includes("fresh ephemeral key test")) && Object.keys(first).sort().join(",") === "ct,eph,iv,kind,recipient,sender,sig,ts,v");
  const incomingCount = await evaluate(bob, "document.querySelectorAll('.message-item--incoming').length");
  async function emit(page, envelope) {
    return evaluate(page, `new Promise(resolve=>e2ee.socket.timeout(5000).emit('send_message',${JSON.stringify(envelope)},(error,result)=>resolve(error?{ok:false}:result)))`);
  }
  await emit(alice, first);
  await wait(bob, "document.getElementById('chat-status').textContent.includes('replayed')");
  check("captured envelope replay dropped using actual IndexedDB seen store", await evaluate(bob, "document.querySelectorAll('.message-item--incoming').length") === incomingCount);
  for (const [name, delta, reason] of [["eight-day-old", -8 * 86400000, "too old"], ["ten-minute-future", 600000, "future"]]) {
    await evaluate(alice, `(async()=>{
      const c=await import('/static/js/crypto.js'),k=await import('/static/js/keystore.js');
      const i=await k.getIdentity('alice'),peer=await(await fetch('/api/users/bob/keys')).json();
      const now=Date.now;let env;
      try{Date.now=()=>now()+(${delta});env=await c.encryptText({ownIdentity:{ecdh:{privateKey:i.ecdhPrivateKey,publicKey:i.ecdhPublicKey},ecdsa:{privateKey:i.ecdsaPrivateKey,publicKey:i.ecdsaPublicKey}},recipientEcdhJwk:peer.ecdh_jwk,sender:'alice',recipient:'bob',text:'timestamp test'});}finally{Date.now=now;}
      await new Promise(resolve=>e2ee.socket.emit('send_message',env,resolve));
    })()`);
    await wait(bob, `document.getElementById('chat-status').textContent.includes(${JSON.stringify(reason)})`);
    check(`${name} signed envelope rejected before rendering`, await evaluate(bob, "document.querySelectorAll('.message-item--incoming').length") === incomingCount);
  }
  const ciphertext = Buffer.from(first.ct, "base64"); ciphertext[0] ^= 1;
  await emit(alice, { ...first, ct: ciphertext.toString("base64") });
  await wait(bob, "document.getElementById('chat-status').textContent.includes('bad signature')");
  check("tampered ciphertext rejected by signature before decryption", await evaluate(bob, "document.querySelectorAll('.message-item--incoming').length") === incomingCount);

  // Regression: queued PNGs addressed to an old recipient key cannot be
  // recovered by resetting that identity. Never weaken verification to show it.
  await evaluate(bob,"void e2ee.socket.disconnect()");
  const oldRecipientKeyPng=await evaluate(alice,`(async()=>{
    const c=await import('/static/js/crypto.js'),k=await import('/static/js/keystore.js'),s=await import('/static/js/stego.js');
    const identity=await k.getIdentity('alice'),peer=await(await fetch('/api/users/bob/keys')).json();
    const canvas=document.createElement('canvas');canvas.width=canvas.height=256;
    const ctx=canvas.getContext('2d');ctx.fillStyle='rgb(40,90,160)';ctx.fillRect(0,0,256,256);
    return (await c.encryptStego({ownIdentity:{ecdh:{privateKey:identity.ecdhPrivateKey,publicKey:identity.ecdhPublicKey},ecdsa:{privateKey:identity.ecdsaPrivateKey,publicKey:identity.ecdsaPublicKey}},
      recipientEcdhJwk:peer.ecdh_jwk,sender:'alice',recipient:'bob',text:'PNG queued before recipient reset',coverBlob:await s.pngBlob(canvas)})).envelope;
  })()`);
  const oldRecipientKeyAck=await emit(alice,oldRecipientKeyPng);
  check('encrypted PNG is queued while recipient is offline before a key reset',oldRecipientKeyAck.ok);
  const oldFingerprint = await evaluate(bob, "document.getElementById('my-fingerprint').textContent");
  await evaluate(bob, "(async()=>{const k=await import('/static/js/keystore.js');await k.clearIdentity('bob');})()");
  await navigate(bob, "/chat");
  await wait(bob, "document.getElementById('my-fingerprint').textContent==='KEYS MISSING'");
  check("lost identity warns without connecting or automatically resetting", !await evaluate(bob, "e2ee.socket.connected") && !bob.uploads.includes("PUT"));
  await evaluate(bob, "document.querySelector('#alert-actions button').click()");
  await wait(bob, identityReady);
  check("explicit reset publishes new keys", bob.uploads.filter((m) => m === "PUT").length === 1 && await evaluate(bob, "document.getElementById('my-fingerprint').textContent") !== oldFingerprint);
  await wait(bob,`document.querySelector('.rejected-delivery[data-delivery-id="${oldRecipientKeyAck.id}"] .rejected-title')?.textContent==='Message could not be decrypted'`);
  check('old-recipient-key PNG stays pending without rendering or acknowledgment',
    !await evaluate(bob,contains('PNG queued before recipient reset'))
    && await evaluate(bob,`fetch('/__test/pending').then(r=>r.json()).then(rows=>rows.some(r=>r.id===${oldRecipientKeyAck.id}))`));
  check('decryption rejection explains key reset and asks for a fresh cover',await evaluate(bob,
    `document.querySelector('.rejected-delivery[data-delivery-id="${oldRecipientKeyAck.id}"] .rejected-detail').textContent.includes('keys were reset') && document.querySelector('.rejected-delivery[data-delivery-id="${oldRecipientKeyAck.id}"] .rejected-detail').textContent.includes('fresh cover PNG')`));
  await select(bob, "alice");
  await send(bob, "untrusted replacement key test");
  await wait(alice, "document.getElementById('chat-status').textContent.includes('explicit trust')");
  check("incoming replacement key is blocked", !await evaluate(alice, contains("untrusted replacement key test")));
  await evaluate(alice, "document.getElementById('message-input').value='must be blocked';document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));");
  await wait(alice, "document.getElementById('alert-title').textContent.includes('Changed') && document.getElementById('send-btn').disabled");
  check("unchanged recipient input still detects peer reset before sending", !await evaluate(bob, contains("must be blocked")));
  await evaluate(alice, "document.querySelector('#alert-actions button').click()");
  await wait(alice, "!document.getElementById('send-btn').disabled");
  await send(alice, "explicitly trusted new key");
  await wait(bob, contains("explicitly trusted new key"));
  await send(bob, "resend after explicit trust");
  await wait(alice, contains("resend after explicit trust"));
  check("both directions work after explicit trust", true);
  check("on-screen contact fingerprint matches peer fingerprint", await evaluate(alice, "document.getElementById('contact-fingerprint').textContent") === await evaluate(bob, "document.getElementById('my-fingerprint').textContent"));
  await evaluate(alice, `{
    const i=document.getElementById('recipient-input');i.value='keyless';i.dispatchEvent(new Event('input'));
    document.getElementById('message-input').value='recipient switching test';
    document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));
  }`);
  await wait(keyless, contains("recipient switching test"));
  const switched = await evaluate(alice, "window.__lastEnvelope");
  const decryptsAsBob = await evaluate(bob, `(async()=>{const c=await import('/static/js/crypto.js'),k=await import('/static/js/keystore.js'),i=await k.getIdentity('bob');try{await c.decryptText({ownEcdhPrivateKey:i.ecdhPrivateKey,env:${JSON.stringify(switched)}});return true;}catch{return false;}})()`);
  check("immediate recipient switching never reuses the previous contact key", switched.recipient === "keyless" && !decryptsAsBob);

  const migration = await page();
  await navigate(migration, "/");
  check("version-1 migration preserves identities, trust and replay records", await evaluate(migration, `(async()=>{
    await new Promise((resolve,reject)=>{const q=indexedDB.open('e2ee-chat',1);q.onupgradeneeded=()=>{const d=q.result;d.createObjectStore('identity',{keyPath:'username'});d.createObjectStore('contacts',{keyPath:'username'});d.createObjectStore('seen',{keyPath:'sigHash'});};q.onerror=reject;q.onsuccess=()=>{const d=q.result,t=d.transaction(['identity','contacts','seen'],'readwrite');t.objectStore('identity').put({username:'alice',marker:'preserved'});t.objectStore('contacts').put({username:'bob',owner:'alice',fingerprint:'SCOPED'});t.objectStore('contacts').put({username:'carol',fingerprint:'LEGACY'});t.objectStore('seen').put({sigHash:'previous-signature'});t.oncomplete=()=>{d.close();resolve();};t.onabort=reject;};});
    const k=await import('/static/js/keystore.js');
    const scoped=await k.getContact('bob','alice'),legacy=await k.getContact('carol','alice');
    await k.saveContact({username:'bob',owner:'charlie',fingerprint:'SEPARATE'});
    return scoped.fingerprint==='SCOPED'&&!scoped.needsReview&&legacy.needsReview&&(await k.getContact('bob','alice')).fingerprint==='SCOPED'&&(await k.getContact('bob','charlie')).fingerprint==='SEPARATE'&&(await k.getIdentity('alice')).marker==='preserved'&&await k.hasSeenSignature('previous-signature');
  })()`));

  const recovery = await page(`{
    const put=IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put=function(...args){const request=put.apply(this,args);if(this.name==='identity'&&!sessionStorage.storageFailureInjected){sessionStorage.storageFailureInjected='1';this.transaction.abort();}return request;};
    const fetchOriginal=window.fetch;
    window.fetch=function(url,options){if(url==='/api/keys'&&!sessionStorage.uploadFailureInjected){sessionStorage.uploadFailureInjected='1';return Promise.resolve(new Response('{}',{status:503}));}return fetchOriginal.call(this,url,options);};
  }`);
  await account(recovery, "carol");
  await wait(recovery, "document.getElementById('alert-title').textContent==='Key setup incomplete'");
  check("storage abort prevents public upload and socket connection", recovery.uploads.length === 0 && !await evaluate(recovery, "e2ee.socket.connected"));
  await evaluate(recovery, "document.querySelector('#alert-actions button').click()");
  await wait(recovery, "sessionStorage.uploadFailureInjected==='1' && document.getElementById('alert-title').textContent==='Key setup incomplete'");
  const savedFingerprint = await evaluate(recovery, "(async()=>{const k=await import('/static/js/keystore.js');return (await k.getIdentity('carol')).fingerprint;})()");
  check("upload failure retains nonextractable identity without connecting", Boolean(savedFingerprint) && !await evaluate(recovery, "e2ee.socket.connected"));
  await navigate(recovery, "/chat");
  await wait(recovery, identityReady);
  check("reload retries the same durable identity after upload failure", recovery.uploads.length === 1 && await evaluate(recovery, "document.getElementById('my-fingerprint').textContent") === savedFingerprint);

  // Step 7: retain a real encrypted offline delivery until rendered and ACKed.
  const pendingRows = () => evaluate(alice, "fetch('/__test/pending').then(r=>r.json())");
  await select(alice, "bob");
  await evaluate(bob,`{
    window.__receiveFetch=window.fetch;
    window.fetch=function(url,options){if(url==='/api/users/alice/keys')return Promise.resolve(new Response('{}',{status:429}));return window.__receiveFetch.call(this,url,options);};
  }`);
  const deferredLookup=await send(alice,'retry after temporary key lookup limit');
  await wait(bob,"Array.from(document.querySelectorAll('.rejected-title')).some(n=>n.textContent==='Public-key lookup temporarily limited')");
  const deferredRow=(await pendingRows()).find(row=>row.ct===deferredLookup.ct);
  check('temporary receive lookup limit has its own reason and retains the row',!!deferredRow
    && !await evaluate(bob,contains('retry after temporary key lookup limit')));
  await evaluate(bob,"window.fetch=window.__receiveFetch;e2ee.socket.disconnect();void e2ee.socket.connect()");
  await wait(bob,contains('retry after temporary key lookup limit'));
  await wait(alice,`fetch('/__test/pending').then(r=>r.json()).then(rows=>!rows.some(row=>row.id===${deferredRow?.id}))`);
  check('retry after temporary lookup failure decrypts and acknowledges normally',true);
  await evaluate(bob, "void e2ee.socket.disconnect()");
  const offlineEnvelope = await send(alice, "offline queued delivery");
  let rows = await pendingRows();
  const offlineRow = rows.find((r) => r.ct === offlineEnvelope.ct);
  check("offline encrypted message is persisted", !!offlineRow);
  await evaluate(bob, "void e2ee.socket.connect()");
  await wait(bob, contains("offline queued delivery"));
  await wait(alice, `fetch('/__test/pending').then(r=>r.json()).then(rows=>!rows.some(r=>r.id===${offlineRow.id}))`);
  check("reconnect decrypts, renders and deletes the queued row", true);

  // Simulate a lost ACK, then redeliver the same database row on reconnect.
  await evaluate(bob, `{
    const original=e2ee.socket.emit;
    window.__savedEmit=original;
    e2ee.socket.emit=function(event,...args){if(event==='ack_message'){args.at(-1)?.(null,{ok:false});return this;}return original.call(this,event,...args);};
  }`);
  const lostAckEnvelope = await send(alice, "lost acknowledgment test");
  await wait(bob, contains("lost acknowledgment test"));
  rows = await pendingRows();
  const lostAckRow = rows.find((r) => r.ct === lostAckEnvelope.ct);
  check("rendered message survives a dropped acknowledgment", !!lostAckRow);
  await evaluate(bob, "e2ee.socket.emit=window.__savedEmit;e2ee.socket.disconnect();void e2ee.socket.connect()");
  await wait(alice, `fetch('/__test/pending').then(r=>r.json()).then(rows=>!rows.some(r=>r.id===${lostAckRow.id}))`);
  check("redelivery is acknowledged again without duplicate rendering", await evaluate(bob, "Array.from(document.querySelectorAll('.message-item--incoming .message-body')).filter(x=>x.textContent==='lost acknowledgment test').length===1"));

  const tampered = { ...offlineEnvelope, ct: Buffer.from(new Uint8Array(Buffer.from(offlineEnvelope.ct,'base64').length)).toString('base64') };
  const tamperedAck = await emit(alice, tampered);
  await wait(bob, "document.getElementById('chat-status').textContent.includes('bad signature')");
  check("tampered delivery is not acknowledged automatically", (await pendingRows()).some(r=>r.id===tamperedAck.id));
  await evaluate(bob, "document.querySelector('.rejected-delivery button').click()");
  // Dismiss all rejection notices; each click is a distinct explicit ACK.
  await evaluate(bob, "document.querySelectorAll('.rejected-delivery button:not(:disabled)').forEach(b=>b.click())");
  await wait(alice, `fetch('/__test/pending').then(r=>r.json()).then(rows=>!rows.some(r=>r.id===${tamperedAck.id}))`);
  check("explicit dismiss deletes a rejected delivery", true);
  await evaluate(bob, "void e2ee.socket.disconnect()");
  const expireEnvelope = await send(alice, "expiry delivery test");
  check("expiry removes undelivered ciphertext", (await pendingRows()).some(r=>r.ct===expireEnvelope.ct)
    && (await evaluate(alice, "fetch('/__test/expire').then(r=>r.json())")).deleted > 0
    && (await pendingRows()).length===0);

  // Step 10: encrypted PNG through the actual chat controls and pending queue.
  const chatFingerprintBeforeNavigation=await evaluate(alice,"document.getElementById('my-fingerprint').textContent");
  await evaluate(alice,"document.querySelector('.stego-send-link').click()");
  await wait(alice,"location.pathname==='/stego' && !!document.querySelector('.transport-card')");
  check('stego button offers exactly image, audio and text transports', await evaluate(alice,
    "Array.from(document.querySelectorAll('.transport-card')).map(a=>a.getAttribute('href')).join(',')==='/stego/image,/stego/audio,/stego/text'"));
  await captureUi('transport-desktop',alice);
  for(const transport of ['audio','text']){
    await navigate(alice,'/stego/'+transport);
    check(transport+' placeholder clearly disables processing and opens no chat socket',await evaluate(alice,
      "!!document.querySelector('fieldset[disabled]') && document.querySelector('.placeholder-panel').textContent.includes('Coming soon') && !window.e2ee"));
    await captureUi(transport+'-placeholder',alice);
  }
  await navigate(alice,'/stego');
  await evaluate(alice,"document.querySelector('a[href=\"/stego/image\"]').click()");
  await wait(alice,"location.pathname==='/stego/image' && window.e2ee?.socket.connected && document.getElementById('my-fingerprint').textContent!=='Loading...'");
  check('image page preserves the saved identity and requires a PNG before sending',await evaluate(alice,
    "document.getElementById('my-fingerprint').textContent==="+JSON.stringify(chatFingerprintBeforeNavigation)+" && document.getElementById('send-btn').disabled && document.querySelector('.chat-panel').dataset.requireCover==='true'"));
  await captureUi('image-desktop',alice);
  await evaluate(alice,`{
    const emit=e2ee.socket.emit;
    e2ee.socket.emit=function(event,...args){if(event==='send_message')window.__lastEnvelope=args[0];return emit.call(this,event,...args);};
    document.getElementById('recipient-input').value='bob';document.getElementById('recipient-input').dispatchEvent(new Event('input'));
    document.getElementById('message-input').value='requires a PNG';document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));
  }`);
  check('image composer refuses a forced submit without a cover instead of sending text',await evaluate(alice,
    "!window.__lastEnvelope && document.getElementById('chat-status').textContent.includes('valid cover')"));
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true},alice.id);
  await wait(alice,"document.getElementById('workspace').dataset.sidebarCollapsed==='true'");
  check('image composer fits a mobile viewport without horizontal overflow',await evaluate(alice,
    "document.documentElement.scrollWidth<=document.documentElement.clientWidth && document.querySelector('.chat-panel').getBoundingClientRect().width>=250 && document.querySelector('.workspace-content').getBoundingClientRect().x>=70"));
  await evaluate(alice,"document.getElementById('sidebar-toggle').click()");
  check('mobile sidebar overlays without squeezing the composer',await evaluate(alice,
    "document.getElementById('workspace').dataset.sidebarCollapsed==='false' && document.querySelector('.chat-panel').getBoundingClientRect().width>=250"));
  await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27},alice.id);
  await wait(alice,"document.getElementById('workspace').dataset.sidebarCollapsed==='true'");
  await captureUi('image-mobile',alice);
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false},alice.id);
  await evaluate(bob, "fetch('/logout',{method:'POST',headers:{'X-CSRFToken':document.querySelector('meta[name=\"csrf-token\"]').content}}).then(r=>r.status)");
  await evaluate(alice, `(async()=>{
    const s=await import('/static/js/stego.js'),canvas=document.createElement('canvas');
    canvas.width=canvas.height=256;const ctx=canvas.getContext('2d');ctx.fillStyle='rgb(80,120,170)';ctx.fillRect(0,0,256,256);
    window.__chatCover=await s.pngBlob(canvas);
    const dt=new DataTransfer();dt.items.add(new File([window.__chatCover],'fresh-cover.png',{type:'image/png'}));
    document.getElementById('cover-image').files=dt.files;document.getElementById('cover-image').dispatchEvent(new Event('change'));
  })()`);
  await wait(alice, "document.getElementById('cover-usage').textContent.includes('capacity') && !document.getElementById('send-btn').disabled");
  check('image composer previews the locally selected PNG',await evaluate(alice,
    "document.getElementById('selected-cover-preview').src.startsWith('blob:') && !document.getElementById('selected-cover-preview').classList.contains('is-hidden')"));
  await evaluate(alice,"document.getElementById('message-input').value='界'.repeat(2000);document.getElementById('message-input').dispatchEvent(new Event('input'))");
  check('chat warns above ten percent capacity using UTF-8 bytes',await evaluate(alice,"document.getElementById('cover-warning').textContent.includes('Above 10%')"));
  const stegoText='offline encrypted PNG message ✓';
  const stegoFirst=await send(alice,stegoText);
  const stegoRow=(await pendingRows()).find(r=>r.ct===stegoFirst.img);
  check('offline stego is stored unchanged with a null IV and no outer ciphertext fields',
    !!stegoRow && stegoRow.kind==='stego' && stegoRow.iv===null
    && Object.keys(stegoFirst).sort().join(',')==='eph,img,kind,recipient,sender,sig,ts,v');
  check('successful stego send clears the attachment and warns to use covers once',await evaluate(alice,
    "document.getElementById('cover-image').files.length===0 && document.querySelector('.chat-panel').textContent.includes('Use each cover image only once')"));
  await evaluate(bob, `(async()=>{const token=document.querySelector('meta[name="csrf-token"]').content;
    await fetch('/login',{method:'POST',body:new URLSearchParams({username:'bob',password:'browser-test-password-123',csrf_token:token})});})()`);
  await navigate(bob,'/chat');await wait(bob,identityReady);await wait(bob,contains(stegoText));
  await wait(alice,`fetch('/__test/pending').then(r=>r.json()).then(rows=>!rows.some(r=>r.id===${stegoRow.id}))`);
  check('offline recipient login verifies, extracts, decrypts, renders and acknowledges stego',true);
  check('saved WSS PNG opens normally and changes RGB by at most one level',await evaluate(alice,`(async()=>{
    const c=await import('/static/js/crypto.js'),s=await import('/static/js/stego.js');
    const original=await s.loadImage(window.__chatCover),stego=await s.loadImage(new Blob([c.fromB64(${JSON.stringify(stegoFirst.img)})],{type:'image/png'}));
    return original.imageData.data.every((v,i)=>i%4===3?v===stego.imageData.data[i]:Math.abs(v-stego.imageData.data[i])<=1);
  })()`));
  // Independent Web Crypto derivation checks both purpose labels and signed bytes.
  await evaluate(bob,`window.__referenceStego=async function(env){
    const c=await import('/static/js/crypto.js'),s=await import('/static/js/stego.js'),k=await import('/static/js/keystore.js');
    const identity=await k.getIdentity('bob');
    const ephemeral=await crypto.subtle.importKey('raw',c.fromB64(env.eph),{name:'ECDH',namedCurve:'P-256'},false,[]);
    const bits=await crypto.subtle.deriveBits({name:'ECDH',public:ephemeral},identity.ecdhPrivateKey,256);
    const shared=await crypto.subtle.importKey('raw',bits,'HKDF',false,['deriveBits','deriveKey']);
    const params={name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32)};
    const positionsKey=new Uint8Array(await crypto.subtle.deriveBits({...params,info:new TextEncoder().encode('stego-positions')},shared,256));
    const aes=await crypto.subtle.deriveKey({...params,info:new TextEncoder().encode('message-encryption')},shared,{name:'AES-GCM',length:256},false,['decrypt']);
    const png=c.fromB64(env.img),payload=await s.extract(new Blob([png],{type:'image/png'}),positionsKey);
    const aad=new TextEncoder().encode('v1|stego|'+env.sender+'|'+env.recipient+'|'+env.ts);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:payload.slice(0,12),tagLength:128,additionalData:aad},aes,payload.slice(12));
    const wrong=await crypto.subtle.importKey('raw',positionsKey,'AES-GCM',false,['decrypt']);let gcmRejected=false;
    try{await crypto.subtle.decrypt({name:'AES-GCM',iv:payload.slice(0,12),tagLength:128,additionalData:aad},wrong,payload.slice(12));}catch{gcmRejected=true;}
    const stream=new s.PositionStream(positionsKey,256*256*3),positions=[];for(let i=0;i<100;i++)positions.push(await stream.next());
    const sender=await(await fetch('/api/users/alice/keys')).json();
    const signatureBytes=new TextEncoder().encode(JSON.stringify(['v1','stego',env.sender,env.recipient,env.ts,env.eph,await c.sha256Hex(png)]));
    const signatureOK=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},await c.importPeerEcdsa(sender.ecdsa_jwk),c.fromB64(env.sig),signatureBytes);
    return {text:new TextDecoder().decode(plain),gcmRejected,positions,signatureOK,iv:c.toB64(payload.slice(0,12))};
  }`);
  const referenceFirst=await evaluate(bob,`window.__referenceStego(${JSON.stringify(stegoFirst)})`);
  check('independent HKDF/AAD/signature reference decrypts and rejects the positions key as AES',referenceFirst.text===stegoText&&referenceFirst.gcmRejected&&referenceFirst.signatureOK);
  check('third account cannot decrypt a captured encrypted PNG',await evaluate(recovery,`(async()=>{
    const c=await import('/static/js/crypto.js'),k=await import('/static/js/keystore.js'),identity=await k.getIdentity('carol');
    try{await c.decryptStego({ownEcdhPrivateKey:identity.ecdhPrivateKey,env:${JSON.stringify(stegoFirst)}});return false;}catch{return true;}
  })()`));
  await evaluate(alice,`(async()=>{const c=await import('/static/js/crypto.js'),k=await import('/static/js/keystore.js'),i=await k.getIdentity('alice'),peer=await(await fetch('/api/users/bob/keys')).json();
    window.__stegoParams={ownIdentity:{ecdh:{privateKey:i.ecdhPrivateKey,publicKey:i.ecdhPublicKey},ecdsa:{privateKey:i.ecdsaPrivateKey,publicKey:i.ecdsaPublicKey}},recipientEcdhJwk:peer.ecdh_jwk,sender:'alice',recipient:'bob',text:${JSON.stringify(stegoText)},coverBlob:window.__chatCover};
    window.__stegoSecond=(await c.encryptStego(window.__stegoParams)).envelope;
  })()`);
  const stegoSecond=await evaluate(alice,'window.__stegoSecond');
  const referenceSecond=await evaluate(bob,`window.__referenceStego(${JSON.stringify(stegoSecond)})`);
  check('same-cover crypto uses fresh ephemeral keys, IVs and different positions',stegoFirst.eph!==stegoSecond.eph&&referenceFirst.iv!==referenceSecond.iv&&referenceFirst.positions.some((v,i)=>v!==referenceSecond.positions[i]));
  await evaluate(alice,`{const dt=new DataTransfer();dt.items.add(new File([window.__chatCover],'same-cover.png',{type:'image/png'}));document.getElementById('cover-image').files=dt.files;document.getElementById('cover-image').dispatchEvent(new Event('change'));}`);
  await wait(alice,"!document.getElementById('send-btn').disabled");
  await evaluate(alice,"document.getElementById('message-input').value='must not reuse cover';document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}))");
  await wait(alice,"document.getElementById('cover-warning').textContent.includes('already used')");
  check('chat blocks accidental cover reuse',await evaluate(alice,'window.__lastEnvelope.img')===stegoFirst.img);
  await evaluate(alice,"document.getElementById('remove-cover').click()");
  await evaluate(bob,'void e2ee.socket.disconnect()');
  const queuedStego=await emit(alice,stegoSecond);
  await evaluate(alice,`fetch('/__test/tamper-png/${queuedStego.id}').then(r=>r.json())`);
  await evaluate(bob,'void e2ee.socket.connect()');
  await wait(bob,"document.getElementById('chat-status').textContent.includes('bad signature')");
  check('single-byte queued PNG tampering fails signature and is not acknowledged',(await pendingRows()).some(r=>r.id===queuedStego.id));
  check('JPEG conversion of encrypted PNG is refused',await evaluate(bob,`(async()=>{
    const c=await import('/static/js/crypto.js'),s=await import('/static/js/stego.js'),k=await import('/static/js/keystore.js'),i=await k.getIdentity('bob');
    const image=await s.loadImage(new Blob([c.fromB64(${JSON.stringify(stegoFirst.img)})],{type:'image/png'}));
    const jpeg=await new Promise(resolve=>image.canvas.toBlob(resolve,'image/jpeg'));
    try{await c.decryptStego({ownEcdhPrivateKey:i.ecdhPrivateKey,env:{...${JSON.stringify(stegoFirst)},img:c.toB64(await jpeg.arrayBuffer())}});return false;}catch{return true;}
  })()`));
  const largeRejected=await evaluate(alice,`(async()=>{
    const c=await import('/static/js/crypto.js'),png=new Uint8Array(3145729);png.set([137,80,78,71,13,10,26,10]);
    return await new Promise(resolve=>e2ee.socket.emit('send_message',{...window.__lastEnvelope,img:c.toB64(png)},resolve));
  })()`);
  check('oversized image gets a clear server rejection',largeRejected.ok===false&&largeRejected.error==='image too large');
  check('sender refuses oversized exported PNG before transmission',await evaluate(alice,`(async()=>{
    const c=await import('/static/js/crypto.js');try{await c.encryptStego({...window.__stegoParams,maxStegoBytes:1});return false;}catch(e){return e.message==='image too large';}
  })()`));
  check('encrypted payload above fifty percent is refused',await evaluate(alice,`(async()=>{
    const c=await import('/static/js/crypto.js');try{await c.encryptStego({...window.__stegoParams,text:'x'.repeat(12257)});return false;}catch(e){return e.message.includes('50%');}
  })()`));

  await evaluate(bob,"Array.from(document.querySelectorAll('.phonebook-entry[data-username=\"alice\"] button')).find(b=>b.textContent==='Remove').click()");
  await wait(alice,"!document.querySelector('.phonebook-entry[data-username=\"bob\"]') && document.getElementById('send-btn').disabled");
  check('removing a contact updates the other phonebook and disables sending',true);
  const afterRemoval=await emit(alice,stegoSecond);
  check('direct encrypted PNG send is rejected after contact removal',!afterRemoval.ok&&afterRemoval.error==='contact not approved');

  await evaluate(alice, "fetch('/logout',{method:'POST',headers:{'X-CSRFToken':document.querySelector('meta[name=\"csrf-token\"]').content}}).then(r=>r.status)");
  await wait(alice, "!e2ee.socket.connected");
  check("HTTP logout disconnects the live browser socket", await evaluate(alice, "fetch('/api/me').then(r=>r.status)") === 401);
  check("no uncaught browser script errors", [...sessions.values()].every((p) => p.errors.length === 0));
  // Step 9 runs in the local-only lab using actual Canvas PNG encoding/decoding.
  const lab = keyless;
  const requestStart = lab.requests.length, socketStart = lab.urls.length;
  await navigate(lab, '/stego-lab');
  await wait(lab, "!!document.getElementById('stego-self-test')");
  await evaluate(lab, `(async()=>{
    const s=await import('/static/js/stego.js');
    const canvas=document.createElement('canvas');canvas.width=canvas.height=256;
    const context=canvas.getContext('2d');context.fillStyle='rgb(80,120,170)';context.fillRect(0,0,256,256);
    window.__cover=await s.pngBlob(canvas);
    const dt=new DataTransfer();dt.items.add(new File([window.__cover],'cover.png',{type:'image/png'}));
    document.getElementById('cover-file').files=dt.files;document.getElementById('cover-file').dispatchEvent(new Event('change'));
    document.getElementById('generate-key').click();
    window.__labKey=document.getElementById('stego-key').value;
    document.getElementById('payload-text').value='<script>alert(1)</script> PNG text ✓';
  })()`);
  await wait(lab, "document.getElementById('lab-status').textContent.includes('PNG ready')");
  await evaluate(lab, "document.getElementById('embed-button').click()");
  await wait(lab, "document.getElementById('lab-status').textContent.includes('Embedding complete')");
  check('lab shows used capacity, changed channels and PNG download', await evaluate(lab,
    "document.getElementById('embed-metrics').textContent.includes('RGB channels changed') && document.getElementById('download-stego').href.startsWith('blob:')"));
  await call('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: auditDirectory, browserContextId: lab.context });
  await evaluate(lab, "document.getElementById('download-stego').click()");
  let downloaded;
  for (let i=0;i<100;i++) {
    try { downloaded=await fs.readFile(path.join(auditDirectory,'stego.png'));break; }
    catch { await sleep(100); }
  }
  assert(downloaded, 'PNG download did not complete');
  await evaluate(lab, `(async()=>{
    window.__stego=new Blob([Uint8Array.from(atob(${JSON.stringify(downloaded?.toString('base64'))}),c=>c.charCodeAt(0))],{type:'image/png'});
    const dt=new DataTransfer();dt.items.add(new File([window.__stego],'stego.png',{type:'image/png'}));
    document.getElementById('extract-file').files=dt.files;document.getElementById('extract-button').click();
  })()`);
  await wait(lab, "document.getElementById('lab-status').textContent.startsWith('Extraction complete')");
  check('lab embed/download/extract returns exact UTF-8 text as harmless DOM text', await evaluate(lab,
    "document.getElementById('extracted-text').textContent===document.getElementById('payload-text').value && document.getElementById('extracted-text').children.length===0"));
  check('PNG changes stay within one RGB level and preserve alpha', await evaluate(lab, `(async()=>{
    const s=await import('/static/js/stego.js'),a=(await s.loadImage(window.__cover)).imageData.data,b=(await s.loadImage(window.__stego)).imageData.data;
    let changes=0;for(let i=0;i<a.length;i++){if(i%4===3&&a[i]!==b[i])return false;if(Math.abs(a[i]-b[i])>1)return false;if(a[i]!==b[i])changes++;}return changes>0;
  })()`));
  const screenshot = await call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, lab.id);
  await fs.writeFile(path.join(auditDirectory,'stego-comparison.png'), Buffer.from(screenshot.data,'base64'));
  console.log('Stego comparison screenshot: '+path.join(auditDirectory,'stego-comparison.png'));
  await evaluate(lab, "document.getElementById('stego-key').value='00'.repeat(32);document.getElementById('extract-button').click()");
  await wait(lab, "!document.getElementById('extract-button').disabled");
  check('wrong key fails cleanly without preserving misleading old output', await evaluate(lab,
    "document.getElementById('extracted-text').textContent!==document.getElementById('payload-text').value"));
  await evaluate(lab, "document.getElementById('stego-key').value=window.__labKey;document.getElementById('stego-self-test').click()");
  await wait(lab, "document.getElementById('lab-status').textContent.includes('self-tests passed')");
  check('all eleven lab self-tests pass, including 100000 unique positions and JPEG rejection', await evaluate(lab,
    "document.getElementById('lab-status').textContent==='11/11 self-tests passed.' && document.querySelectorAll('#self-test-results li').length===11"));
  check('PNG dimension limits reject undersized and oversized images before decode', await evaluate(lab, `(async()=>{
    const s=await import('/static/js/stego.js');
    for(const width of [255,4097]){const header=new Uint8Array(await window.__cover.arrayBuffer());new DataView(header.buffer).setUint32(16,width,false);try{await s.loadImage(new Blob([header],{type:'image/png'}));return false;}catch(e){if(!e.message.includes('dimensions'))return false;}}
    return true;
  })()`));
  await evaluate(lab, "document.getElementById('payload-text').value='x'.repeat(3000);document.getElementById('payload-text').dispatchEvent(new Event('input'))");
  check('usage above ten percent is visibly warned', await evaluate(lab,
    "document.getElementById('capacity-warning').textContent.includes('Above 10%')"));
  await evaluate(lab, "document.getElementById('payload-text').value='x'.repeat(12285);document.getElementById('embed-button').click()");
  await wait(lab, "!document.getElementById('embed-button').disabled");
  check('lab refuses payload above fifty percent and clears obsolete download', await evaluate(lab,
    "document.getElementById('lab-status').textContent.includes('50%') && document.getElementById('download-stego').classList.contains('is-hidden')"));
  check('lab sends no images, payload text or secret keys to the server and opens no sockets',
    lab.urls.length===socketStart && lab.requests.slice(requestStart).filter(r=>r.url.startsWith(base)).every(r=>r.method==='GET'&&!r.body));

  // Optional Step 11 artifacts: synthetic cover and real encrypted PNGs only.
  // SECURITY: fresh test identities remain in browser memory; never export keys.
  if (process.env.STEGO_ANALYSIS_DIR) {
    const directory = path.resolve(process.env.STEGO_ANALYSIS_DIR);
    const experiments = await evaluate(lab, `(async()=>{
      const c=await import('/static/js/crypto.js'),s=await import('/static/js/stego.js');
      const canvas=document.createElement('canvas');canvas.width=canvas.height=256;
      const context=canvas.getContext('2d'),pixels=context.createImageData(256,256);
      // Intentionally even-valued gradient: a controlled histogram demonstration,
      // not a claim about the statistics of natural photographs.
      for(let y=0;y<256;y++)for(let x=0;x<256;x++){
        const i=(y*256+x)*4;pixels.data[i]=2*(x>>1);pixels.data[i+1]=2*(y>>1);
        pixels.data[i+2]=2*(((x+y)>>2)%128);pixels.data[i+3]=255;
      }
      context.putImageData(pixels,0,0);const cover=await s.pngBlob(canvas);
      const ownIdentity=await c.generateIdentity(),recipientIdentity=await c.generateIdentity();
      const recipientEcdhJwk=await c.exportPublicJwk(recipientIdentity.ecdh.publicKey);
      const results=[];
      for(const [name,plaintextBytes] of [['low_fill',100],['high_fill',12256]]){
        const text='A'.repeat(plaintextBytes);
        const result=await c.encryptStego({ownIdentity,recipientEcdhJwk,
          sender:'analysis_sender',recipient:'analysis_recipient',text,coverBlob:cover});
        const env=result.envelope;
        const signed=new TextEncoder().encode(JSON.stringify(['v1','stego',env.sender,env.recipient,env.ts,env.eph,await c.sha256Hex(c.fromB64(env.img))]));
        const signatureOK=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},ownIdentity.ecdsa.publicKey,c.fromB64(env.sig),signed);
        const roundTrip=await c.decryptStego({ownEcdhPrivateKey:recipientIdentity.ecdh.privateKey,env})===text;
        results.push({name,png:env.img,plaintextBytes,encryptedPayloadBytes:plaintextBytes+28,
          framedBytes:plaintextBytes+32,usedFraction:result.usedFraction,
          changedChannels:result.changedChannels,signatureOK,roundTrip});
      }
      return {cover:c.toB64(new Uint8Array(await cover.arrayBuffer())),results};
    })()`);
    await fs.mkdir(directory, { recursive: true });
    await fs.writeFile(path.join(directory,'cover.png'),Buffer.from(experiments.cover,'base64'));
    const manifest={width:256,height:256,mode:'LSB replacement',
      cover:'Synthetic even-valued RGB gradient; deliberately histogram-biased, not a photograph.',
      fillDefinition:'(UTF-8 plaintext + 12-byte IV + 16-byte GCM tag + 4-byte length) * 8 / RGB channels',
      experiments:[]};
    for(const {png,...measurement} of experiments.results){
      await fs.writeFile(path.join(directory,measurement.name+'.png'),Buffer.from(png,'base64'));
      manifest.experiments.push(measurement);
      check('Step 11 '+measurement.name+' signature and encrypted PNG round trip',
        measurement.signatureOK && measurement.roundTrip);
    }
    check('Step 11 experiments use under ten percent and exactly fifty percent capacity',
      manifest.experiments[0].usedFraction<0.1 && manifest.experiments[1].usedFraction===0.5);
    await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
    console.log('Synthetic Step 11 analysis inputs: '+directory);
  }

  const cspPage = await page(`document.addEventListener('securitypolicyviolation', event => {
    (window.__cspViolations ||= []).push(event.violatedDirective);
  });`);
  await navigate(cspPage, '/__test/csp-experiment');
  await wait(cspPage, 'window.__cspViolations?.length > 0');
  check('strict CSP blocks an inline script in a rendered test template', await evaluate(cspPage,
    "window.__inlineExecuted!==true && window.__cspViolations.some(d=>d.startsWith('script-src'))"));
  const headers = await new Promise((resolve, reject) => {
    https.get(base + '/login', { ca }, response => { response.resume(); resolve(response.headers); }).on('error', reject);
  });
  check('real HTTPS responses include CSP, HSTS and nosniff',
    headers['content-security-policy']?.includes("script-src 'self'")
    && headers['strict-transport-security']==='max-age=3600'
    && headers['x-content-type-options']==='nosniff');
  const audit = await fs.readFile(path.join(auditDirectory, 'audit.log'), 'utf8');
  check('browser audit contains account and key events without message content',
    ['registration','login_success','keys_uploaded','keys_reset','logout'].every(event=>audit.includes('event='+event))
    && !audit.includes('browser-test-password-123') && !audit.includes(first.ct) && !audit.includes(text));
  console.log(`Browser acceptance: ${passed} passed, ${failures.length} failed`);
  if (failures.length) process.exitCode = 1;
} catch (error) {
  console.error(error.stack);
  process.exitCode = 1;
} finally {
  ws?.close();
  // Windows venv launchers and Chrome have children: stop only our own trees.
  for (const child of [browser, server]) {
    if (!child?.pid) continue;
    if (process.platform === "win32") {
      await new Promise((resolve) => {
        const stop = spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
        stop.on("exit", resolve); stop.on("error", resolve);
      });
    } else child.kill();
  }
}
