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
from flask import jsonify, render_template_string
from datetime import datetime, timedelta, timezone
from cleanup import delete_expired_messages
class ReviewConfig(Config):
 TESTING=True
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
 return jsonify([{'id':m.id,'ct':m.ciphertext,'sig':m.signature} for m in PendingMessage.query.all()])
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
    const result = { id: sessionId, uploads: [], urls: [], frames: [], errors: [] };
    sessions.set(sessionId, result);
    await call("Page.enable", {}, sessionId);
    await call("Network.enable", {}, sessionId);
    await call("Runtime.enable", {}, sessionId);
    if (script) await call("Page.addScriptToEvaluateOnNewDocument", { source: script }, sessionId);
    return result;
  }
  async function navigate(page, route) {
    await evaluate(page, "window.__previousDocument = true");
    const result = await call("Page.navigate", { url: base + route }, page.id);
    assert(!result.errorText, result.errorText);
    await wait(page, "!window.__previousDocument && document.readyState === 'complete' && !!document.querySelector('meta[name=\"csrf-token\"]')");
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
  const alice = await page(uploadProbe), bob = await page(uploadProbe);
  await account(alice, "alice"); await account(bob, "bob");
  const identityReady = "window.e2ee?.socket.connected && /^[0-9A-F]{4} /.test(document.getElementById('my-fingerprint').textContent)";
  await wait(alice, identityReady); await wait(bob, identityReady);
  check("two isolated browser sessions load trusted HTTPS with Web Crypto", await evaluate(alice, "isSecureContext && !!crypto.subtle"));
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
    await evaluate(page, `{document.getElementById('message-input').value=${JSON.stringify(text)};document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));}`);
    await wait(page, `document.getElementById('chat-status').textContent==='Message sent' && document.getElementById('message-input').value===''`);
    return evaluate(page, "window.__lastEnvelope");
  }
  const contains = (text) => `Array.from(document.querySelectorAll('.message-item--incoming .message-body')).some(x=>x.textContent===${JSON.stringify(text)})`;
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

  const oldFingerprint = await evaluate(bob, "document.getElementById('my-fingerprint').textContent");
  await evaluate(bob, "(async()=>{const k=await import('/static/js/keystore.js');await k.clearIdentity('bob');})()");
  await navigate(bob, "/chat");
  await wait(bob, "document.getElementById('my-fingerprint').textContent==='KEYS MISSING'");
  check("lost identity warns without connecting or automatically resetting", !await evaluate(bob, "e2ee.socket.connected") && !bob.uploads.includes("PUT"));
  await evaluate(bob, "document.querySelector('#alert-actions button').click()");
  await wait(bob, identityReady);
  check("explicit reset publishes new keys", bob.uploads.filter((m) => m === "PUT").length === 1 && await evaluate(bob, "document.getElementById('my-fingerprint').textContent") !== oldFingerprint);
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
    const i=document.getElementById('recipient-input');i.value='alice';i.dispatchEvent(new Event('input'));
    document.getElementById('message-input').value='recipient switching test';
    document.getElementById('chat-form').dispatchEvent(new Event('submit',{cancelable:true}));
  }`);
  await wait(alice, contains("recipient switching test"));
  const switched = await evaluate(alice, "window.__lastEnvelope");
  const decryptsAsBob = await evaluate(bob, `(async()=>{const c=await import('/static/js/crypto.js'),k=await import('/static/js/keystore.js'),i=await k.getIdentity('bob');try{await c.decryptText({ownEcdhPrivateKey:i.ecdhPrivateKey,env:${JSON.stringify(switched)}});return true;}catch{return false;}})()`);
  check("immediate recipient switching never reuses the previous contact key", switched.recipient === "alice" && !decryptsAsBob);

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

  await evaluate(alice, "fetch('/logout',{method:'POST',headers:{'X-CSRFToken':document.querySelector('meta[name=\"csrf-token\"]').content}}).then(r=>r.status)");
  await wait(alice, "!e2ee.socket.connected");
  check("HTTP logout disconnects the live browser socket", await evaluate(alice, "fetch('/api/me').then(r=>r.status)") === 401);
  check("no uncaught browser script errors", [...sessions.values()].every((p) => p.errors.length === 0));
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
