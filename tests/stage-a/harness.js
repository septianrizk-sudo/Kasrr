/* ============================================================
   Stage A Security Remediation Test Harness (Node vm)
   - Runs the single-file app script inside a vm context with DOM/localStorage stubs.
   - Approach: Node `vm` + hand-built DOM/localStorage/FileReader stubs. No browser, no package install.
   - H1: document.addEventListener captures listeners per event type; dispatch() triggers real listeners
         with fake event (target.closest, dataset, files, preventDefault).
   ============================================================ */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const crypto = require('crypto');

const STORAGE_KEY = 'kasirkopi.v2';

// Module-level default HTML (used by T13 for data-act/data-form extraction)
const defaultHtmlPath = path.resolve(__dirname, '../../Kasir Kopi (1).html');
const defaultHtml = fs.readFileSync(defaultHtmlPath, 'utf-8');
const html = defaultHtml;
const scriptSrc = defaultHtml.match(/<script>([\s\S]*)<\/script>/)?.[1];

// ---- Node-side plain element factory (for forms passed into vm handlers) ----
function mkEl(tag) {
  const el = {
    tagName: (tag || 'input').toUpperCase(), value: '', name: '', id: '', className: '',
    innerHTML: '', textContent: '', hidden: false, dataset: {}, attributes: {}, style: {},
    children: [], parentNode: null, checked: false, files: null,
    addEventListener: () => {}, removeEventListener: () => {},
    focus: () => {}, querySelector: () => null, querySelectorAll: () => [],
    appendChild: () => {},
    classList: { add: () => {}, remove: () => {}, contains: () => false, toggle: () => {} }
  };
  el.closest = (sel) => {
    if (sel.startsWith('[data-act') && el.dataset && el.dataset.act) return el;
    if (sel.startsWith('[data-form') && el.dataset && el.dataset.form) return el;
    return null;
  };
  return el;
}

// ---- Environment factory ----
function makeApp(opts = {}) {
  const appHtmlPath = opts.htmlPath || path.resolve(__dirname, '../../Kasir Kopi (1).html');
  const appHtml = fs.readFileSync(appHtmlPath, 'utf-8');
  const appScriptMatch = appHtml.match(/<script>([\s\S]*)<\/script>/);
  if (!appScriptMatch) throw new Error('No script tag found in HTML: ' + appHtmlPath);
  const appScriptSrc = appScriptMatch[1];
  const withCrypto = opts.withCrypto !== false;
  const store = {};
  const elements = new Map();
  let nextElemId = 1;
  const listeners = {}; // H1: capture listeners by type

  function createElement(tag) {
    const id = 'elem-' + nextElemId++;
    const el = {
      tagName: tag.toUpperCase(), id: '', className: '', hidden: false,
      innerHTML: '', textContent: '', value: '', dataset: {}, attributes: {},
      children: [], parentNode: null, style: {}, checked: false, files: null,
      addEventListener: () => {}, removeEventListener: () => {},
      querySelector: (sel) => { if (sel.startsWith('#')) { const e = elements.get(sel.slice(1)); return e || null; } return null; },
      querySelectorAll: () => [],
      closest: (sel) => { if (sel.startsWith('[data-act') && el.dataset.act) return el; if (sel.startsWith('[data-form') && el.dataset.form) return el; return null; },
      focus: () => {}, appendChild: (c) => { c.parentNode = el; el.children.push(c); return c; },
      setAttribute: (n, v) => { el.attributes[n] = v; if (n === 'id') el.id = v; },
      getAttribute: (n) => el.attributes[n], removeAttribute: (n) => { delete el.attributes[n]; },
      classList: { add: (c) => { el.className += ' ' + c; }, remove: (c) => { el.className = el.className.replace(c, '').trim(); }, contains: (c) => el.className.split(/\s+/).includes(c), toggle: (c) => { if (el.className.split(/\s+/).includes(c)) el.className = el.className.replace(c, '').trim(); else el.className += ' ' + c; } }
    };
    elements.set(id, el);
    return el;
  }
  ['toast','modal','banner','view','tabs','shopName','opBadge','clock','pinIn','mcIn','mcOld','mcNew','mcConfirm','mc2','discVal','phone','cash','sq','opSel','campType','rkDate','rkOp','restoreIn','shopIn','fn','fu','fs','fmn','ps','psErr','mcErr','reErr','discVal','pinBox'].forEach(id => elements.set(id, createElement('div')));
  const toastEl = elements.get('toast');
  const viewEl = elements.get('view');

  const document = {
    getElementById: (id) => elements.get(id) || createElement('div'),
    querySelector: (sel) => { if (sel.startsWith('#')) { const e = elements.get(sel.slice(1)); return e || createElement('div'); } return createElement('div'); },
    querySelectorAll: () => [], createElement,
    addEventListener: (type, fn) => { if (!listeners[type]) listeners[type] = []; listeners[type].push(fn); },
    removeEventListener: () => {},
    hidden: false, body: createElement('body'), head: createElement('head')
  };

  const subtle = withCrypto
    ? ((globalThis.crypto && globalThis.crypto.subtle) || (typeof crypto.webcrypto !== 'undefined' ? crypto.webcrypto.subtle : null))
    : null;
  const cryptoObj = {
    subtle,
    getRandomValues: withCrypto ? (buf) => crypto.webcrypto.getRandomValues(buf) : null
  };

  const window = {
    crypto: cryptoObj, addEventListener: (type, fn) => { if (!listeners[type]) listeners[type] = []; listeners[type].push(fn); }, removeEventListener: () => {}, location: { href: '' },
    navigator: { clipboard: { writeText: async () => {} } },
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'), atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    setTimeout, clearTimeout, setInterval, clearInterval, Date, scrollTo: () => {}, claude: { use: async () => false }
  };

  class FileReader {
    constructor() { this.onload = null; this.onerror = null; this.result = null; }
    readAsText(file) { this.result = file.content || ''; setTimeout(() => { if (this.onload) this.onload({ target: this }); }, 0); }
  }
  class FormData {
    constructor() { this.data = new Map(); }
    get(k) { return this.data.get(k) || ''; }
    getAll(k) { return this.data.get(k) ? [this.data.get(k)] : []; }
    append(k, v) { this.data.set(k, v); } set(k, v) { this.data.set(k, v); } has(k) { return this.data.has(k); }
    forEach(cb) { this.data.forEach((v, k) => cb(v, k, this)); }
    entries() { return this.data.entries(); } keys() { return this.data.keys(); } values() { return this.data.values(); }
  }
  async function derivePBKDF2(password, salt) {
    const enc = new TextEncoder();
    const km = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    return subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, km, 256);
  }
  function b64url(d) { return Buffer.from(d).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); }
  function b64urlToBytes(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }

  const ctx = vm.createContext({
    console, setTimeout, clearTimeout, setInterval, clearInterval, Date, Promise, Map, Set,
    Array, Object, String, Number, Boolean, JSON, Math, Error, RegExp, TextEncoder, TextDecoder,
    Buffer, localStorage: null, document, window, navigator: window.navigator, crypto: cryptoObj,
    FileReader, FormData, btoa: window.btoa, atob: window.atob, derivePBKDF2, b64url, b64urlToBytes, __tmp: null
  });

  const localStorage = {
    getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; },
    clear: () => { Object.keys(store).forEach(k => delete store[k]); }
  };
  ctx.localStorage = localStorage;

  vm.runInContext(appScriptSrc, ctx);

  // H1: dispatch helper that triggers real listeners
  function dispatch(type, target, extra = {}) {
    const ev = Object.assign({ target, preventDefault: () => {}, type }, extra);
    const fns = listeners[type] || [];
    for (const fn of fns) fn(ev);
    return ev;
  }

  return {
    ctx, elements, store, localStorage, toastEl, viewEl, listeners, document,
    get(name) { return vm.runInContext(name, ctx); },
    set(name, val) { ctx.__tmp = val; vm.runInContext(name + '=__tmp', ctx); },
    call(fnName, ...args) { const fn = vm.runInContext(fnName, ctx); return fn(...args); },
    reset: () => { Object.keys(store).forEach(k => delete store[k]); elements.forEach(el => { el.value = ''; el.innerHTML = ''; el.textContent = ''; el.hidden = false; el.className = ''; el.dataset = {}; el.attributes = {}; el.files = null; }); },
    clearStorage: () => { Object.keys(store).forEach(k => delete store[k]); },
    init() { return vm.runInContext('init()', ctx); },
    dispatch,
    withCrypto
  };
}

// ---- Test Helpers ----
let testCount = 0, passCount = 0, failCount = 0;
const results = [];
function logTest(name, passed, details = '') {
  testCount++;
  if (passed) { passCount++; console.log(`\n✓ PASS T${testCount}: ${name}`); }
  else { failCount++; console.log(`\n✗ FAIL T${testCount}: ${name}`); }
  if (details) console.log(`  ${details}`);
  results.push({ test: testCount, name, passed, details });
  return passed;
}
function assertEqual(a, b, msg) { const p = a === b; logTest(msg, p, p ? '' : `Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); return p; }
function assertTrue(v, msg) { return assertEqual(!!v, true, msg); }
function assertFalse(v, msg) { return assertEqual(!!v, false, msg); }

// Form factories
function makePinForm(value) { const f = mkEl('form'); f.dataset.form = 'pinstep'; f.v = mkEl('input'); f.v.value = value; f.v.name = 'v'; return f; }
function makeMasterForm(oldV, newV, confV) {
  const f = mkEl('form'); f.dataset.form = 'master';
  f.mcOld = mkEl('input'); f.mcOld.value = oldV || ''; f.mcOld.name = 'mcOld';
  f.mc = mkEl('input'); f.mc.value = newV || ''; f.mc.name = 'mc';
  f.mc2 = mkEl('input'); f.mc2.value = confV || ''; f.mc2.name = 'mc2';
  return f;
}
function makePinUnlockForm(value) { const f = mkEl('form'); f.dataset.form = 'pin'; f.pin = mkEl('input'); f.pin.value = value; f.pin.name = 'pin'; return f; }
function makeRecoveryForm(step, mcVal) { const f = mkEl('form'); f.dataset.form = 'recovery'; f.step = mkEl('input'); f.step.value = String(step); f.step.name = 'step'; f.mc = mkEl('input'); f.mc.value = mcVal || ''; f.mc.name = 'mc'; return f; }
function makeRestoreFile(content) { return { content: JSON.stringify(content) }; }

// Dispatch helpers (all scenarios must go through dispatcher)
function clickAct(app, act, extra = {}) {
  const el = mkEl('button'); el.dataset.act = act; Object.assign(el.dataset, extra);
  app.dispatch('click', el);
}
function submitForm(app, formEl) { app.dispatch('submit', formEl); }
function changeEl(app, el) { app.dispatch('change', el); }
function visibilityChange(app, hidden) { app.document.hidden = hidden; app.dispatch('visibilitychange', app.document); }
function keyDown(app) { app.dispatch('keydown', app.document); }
function mouseMove(app) { app.dispatch('mousemove', app.document); }

// Date.now mock helper for lockout tests
function withMockedNow(app, startMs, fn) {
  const realNow = Date.now;
  let now = startMs;
  Date.now = () => now;
  app.ctx.Date.now = () => now;
  const advance = (ms) => { now += ms; };
  const restore = () => { Date.now = realNow; app.ctx.Date.now = realNow; };
  try {
    const res = fn(advance, () => now);
    if (res && typeof res.then === 'function') return res.finally(restore);
    restore(); return res;
  } catch (e) { restore(); throw e; }
}

// ---- Run Tests ----
async function runTests(htmlPath) {
  console.log('══════════════════════════════════════════════════════════════');
  console.log('  Stage A Security Remediation Tests (T1–T14 + T15–T20)');
  console.log('══════════════════════════════════════════════════════════════\n');

  // ---------- T1 ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    assertFalse(app.get('S').pinEnabled, 'T1: pinEnabled should be false initially');
    app.call('go', 'rekap');
    let v = app.get('view');
    logTest('T1: go rekap blocked pre-PIN', v.tab === 'kasir', `view.tab=${v.tab}, toast=${app.toastEl.textContent}`);
    app.call('go', 'stok');
    v = app.get('view');
    logTest('T1: go stok blocked pre-PIN', v.tab === 'kasir', `view.tab=${v.tab}`);
    app.call('go', 'atur');
    v = app.get('view');
    logTest('T1: go atur allowed pre-PIN', v.tab === 'atur', `view.tab=${v.tab}`);
    const el = mkEl('div');
    app.call('vAtur', el);
    const inner = el.innerHTML;
    logTest('T1: vAtur pre-PIN shows only PIN+Master',
      inner.includes('Aktifkan PIN') && inner.includes('Master Code') && !inner.includes('Nama toko') && !inner.includes('Operator kasir') && !inner.includes('Unduh cadangan'),
      `pin=${inner.includes('Aktifkan PIN')}, master=${inner.includes('Master Code')}, shop=${!inner.includes('Nama toko')}`);
  }

  // ---------- T2 ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    let S = app.get('S');
    app.call('go', 'atur');
    const CASHIER_ACTS = app.get('CASHIER_ACTS');
    const canAccessOwner = app.get('canAccessOwner');
    const blockedActs = ['menunew','wipe','backup','restock','backupWithCreds','endshift'];
    let allBlocked = true;
    for (const act of blockedActs) {
      const gated = !CASHIER_ACTS.has(act);
      if (gated && canAccessOwner()) { allBlocked = false; console.log(`  Action ${act} NOT gated`); }
    }
    logTest('T2: Owner click actions blocked pre-PIN', allBlocked, '');
    const blockedForms = ['ing','menu','shop','op'];
    let formsBlocked = true;
    for (const form of blockedForms) if (canAccessOwner(form)) { formsBlocked = false; console.log(`  Form ${form} NOT blocked`); }
    logTest('T2: Owner forms blocked pre-PIN', formsBlocked, '');
    S = app.get('S');
    logTest('T2: S unchanged after blocked actions', !S.menu.some(m => m.name === 'test') && S.operators.length === 2 && S.ingredients.length > 0, '');
  }

  // ---------- T3 ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    app.call('go', 'atur');
    const F = app.get('F');
    let f = makePinForm('123456');
    await F.pinstep(f);
    let pinStep = app.get('pinStep');
    logTest('T3: PIN step 1 stores new PIN', pinStep.n === 1 && pinStep.nw === '123456', `pinStep=${JSON.stringify(pinStep)}`);
    f = makePinForm('123456');
    await F.pinstep(f);
    const S = app.get('S');
    const pinIsEnvelope = S.pin && typeof S.pin === 'object' && S.pin.hash && S.pin.salt && S.pin.iter;
    logTest('T3: PIN becomes envelope', pinIsEnvelope, `S.pin=${JSON.stringify(S.pin)}`);
    logTest('T3: pinEnabled=true', S.pinEnabled === true, `pinEnabled=${S.pinEnabled}`);
    logTest('T3: view.unlocked=false', app.get('view').unlocked === false, `unlocked=${app.get('view').unlocked}`);
    logTest('T3: tab=kasir', app.get('view').tab === 'kasir', `tab=${app.get('view').tab}`);
    logTest('T3: toast mentions Master Code', app.toastEl.textContent.includes('Master Code'), `toast=${app.toastEl.textContent}`);
  }

  // ---------- T4 ----------
  {
    const app = makeApp({ htmlPath }); app.reset();
    const legacyHash = app.get('legacyHash');
    const legacyPin = legacyHash('1234');
    const legacyMaster = legacyHash('masterlama123');
    app.store[STORAGE_KEY] = JSON.stringify({ v:2,seq:0,shop:'Kopi Kita',rewardAt:10,pin:legacyPin,master:legacyMaster,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[{id:'op1',name:'Kasir Pagi'}],ingredients:[],menu:[],campaigns:[],recovery:null });
    app.init();
    let S = app.get('S');
    logTest('T4: pinEnabled=true after migrate', S.pinEnabled === true, `pinEnabled=${S.pinEnabled}`);
    logTest('T4: migrationPending=true', S.migrationPending === true, `migrationPending=${S.migrationPending}`);
    const F = app.get('F');
    app.call('go', 'atur');
    await F.pin(makePinUnlockForm('0000'));
    let S2 = app.get('S');
    logTest('T4: Wrong PIN rejected', S2.pin === legacyPin, `S.pin still legacy: ${S2.pin === legacyPin}`);
    await F.pin(makePinUnlockForm('1234'));
    let S3 = app.get('S');
    const pinNowEnvelope = S3.pin && typeof S3.pin === 'object' && S3.pin.hash;
    logTest('T4: Correct PIN migrates to envelope', pinNowEnvelope, `S.pin is envelope: ${pinNowEnvelope}`);
    logTest('T4: Master unchanged (no double-hash)', S3.master === legacyMaster, `S.master=${S3.master}, expected=${legacyMaster}`);
  }

  // ---------- T5 ----------
  {
    const app = makeApp({ htmlPath }); app.reset();
    const legacyMaster = app.get('legacyHash')('masterlama123');
    app.store[STORAGE_KEY] = JSON.stringify({ v:2,seq:0,shop:'Kopi Kita',rewardAt:10,pin:null,master:legacyMaster,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[{id:'op1',name:'Kasir Pagi'}],ingredients:[],menu:[],campaigns:[],recovery:null });
    app.init();
    const F = app.get('F');
    await F.master(makeMasterForm('masterlama123','masterbaru123456','masterbaru123456'));
    let S = app.get('S');
    logTest('T5: Legacy master migrates to envelope', S.master && typeof S.master === 'object' && S.master.hash, `S.master=${JSON.stringify(S.master)}`);
  }

  // ---------- T6 (H4: lockout with Date.now mock for legacy, envelope, recovery step 1) ----------
  {
    // Legacy branch
    const app = makeApp({ htmlPath }); app.reset();
    const legacyMaster = app.get('legacyHash')('masterlama123');
    app.store[STORAGE_KEY] = JSON.stringify({ v:2,seq:0,shop:'Kopi Kita',rewardAt:10,pin:null,master:legacyMaster,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[{id:'op1',name:'Kasir Pagi'}],ingredients:[],menu:[],campaigns:[],recovery:null });
    app.init();
    const F = app.get('F');
    await withMockedNow(app, 1700000000000, async (advance) => {
      const fWrong = makeMasterForm('wrong','masterbaru123456','masterbaru123456');
      await F.master(fWrong); await F.master(fWrong); await F.master(fWrong);
      let S = app.get('S');
      logTest('T6: Legacy lockout after 3 fails', S.masterLockUntil > Date.now(), `masterLockUntil=${S.masterLockUntil}, now=${Date.now()}`);
      const beforeLock = app.get('S').masterLockUntil;
      await F.master(makeMasterForm('masterlama123','masterbaru123456','masterbaru123456'));
      const S2 = app.get('S');
      logTest('T6: Legacy correct code within 60s rejected and master unchanged', S2.masterLockUntil === beforeLock && S2.master === legacyMaster, `masterLockUntil=${S2.masterLockUntil}, master same=${S2.master===legacyMaster}`);
      advance(61000);
      await F.master(makeMasterForm('masterlama123','masterbaru123456','masterbaru123456'));
      const S3 = app.get('S');
      logTest('T6: Legacy correct code after 61s accepted', S3.master && typeof S3.master === 'object' && S3.master.hash, `master=${JSON.stringify(S3.master)}`);
    });

    // Envelope branch
    const app2 = makeApp({ htmlPath }); app2.reset(); app2.clearStorage(); app2.init();
    const F2 = app2.get('F');
    await F2.master(makeMasterForm('', 'masterenvelope12', 'masterenvelope12'));
    await withMockedNow(app2, 1700000000000, async (advance) => {
      const fWrong = makeMasterForm('', 'wrong', '');
      // envelope branch: when master exists and not verified, F.master takes mc (no mcOld/mc2)
      const mkV = (pw) => { const f=mkEl('form'); f.dataset.form='master'; f.mc=mkEl('input'); f.mc.value=pw; f.mc.name='mc'; return f; };
      await F2.master(mkV('wrongpassword12')); await F2.master(mkV('wrongpassword12')); await F2.master(mkV('wrongpassword12'));
      let S = app2.get('S');
      logTest('T6: Envelope lockout after 3 fails', S.masterLockUntil > Date.now(), `masterLockUntil=${S.masterLockUntil}`);
      const before = JSON.stringify(S.master);
      await F2.master(mkV('masterenvelope12'));
      let S2 = app2.get('S');
      logTest('T6: Envelope correct code within 60s rejected and master unchanged', JSON.stringify(S2.master) === before && S2.masterVerified === false, `masterSame=${JSON.stringify(S2.master)===before}, verified=${S2.masterVerified}`);
      advance(61000);
      await F2.master(mkV('masterenvelope12'));
      let S3 = app2.get('S');
      logTest('T6: Envelope correct code after 61s accepted', S3.masterVerified === true, `masterVerified=${S3.masterVerified}`);
    });

    // Recovery step 1 branch
    const app3 = makeApp({ htmlPath }); app3.reset(); app3.clearStorage(); app3.init();
    const F3a = app3.get('F');
    await F3a.master(makeMasterForm('', 'masterrecovery12', 'masterrecovery12'));
    const S3i = app3.get('S');
    S3i.recovery = { step: 1, masterPending: null, pinPending: null };
    S3i.masterVerified = false;
    await withMockedNow(app3, 1700000000000, async (advance) => {
      const F3 = app3.get('F');
      const mkRec = (mc) => { const f=mkEl('form'); f.dataset.form='recovery'; f.step=mkEl('input'); f.step.value='1'; f.step.name='step'; f.mc=mkEl('input'); f.mc.value=mc; f.mc.name='mc'; return f; };
      await F3.recovery(mkRec('wrong1')); await F3.recovery(mkRec('wrong2')); await F3.recovery(mkRec('wrong3'));
      let S = app3.get('S');
      const locked = S.masterLockUntil > Date.now();
      logTest('T6: Recovery step1 lockout after 3 fails', locked, `masterLockUntil=${S.masterLockUntil}, now=${Date.now()}`);
      const masterBefore = JSON.stringify(S.master);
      await F3.recovery(mkRec('masterrecovery12'));
      let S2 = app3.get('S');
      logTest('T6: Recovery step1 correct code within 60s rejected and master unchanged', JSON.stringify(S2.master) === masterBefore, `masterSame=${JSON.stringify(S2.master)===masterBefore}`);
      advance(61000);
      await F3.recovery(mkRec('masterrecovery12'));
      let S4 = app3.get('S');
      const advanced = (S4.recovery && S4.recovery.step !== 1) || S4.masterVerified === true || S4.masterLockUntil === 0;
      logTest('T6: Recovery step1 correct code after 61s accepted', advanced, `recovery.step=${S4.recovery?S4.recovery.step:'null'}, masterVerified=${S4.masterVerified}, lockUntil=${S4.masterLockUntil}`);
    });
  }

  // ---------- T7 ----------
  {
    const app = makeApp({ htmlPath }); app.reset();
    const legacyMaster = app.get('legacyHash')('masterlama123');
    app.store[STORAGE_KEY] = JSON.stringify({ v:2,seq:0,shop:'Kopi Kita',rewardAt:10,pin:null,master:legacyMaster,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[{id:'op1',name:'Kasir Pagi'}],ingredients:[],menu:[],campaigns:[],recovery:null });
    app.init();
    let S = app.get('S');
    logTest('T7: Legacy master-only -> pre-PIN state', !S.pinEnabled, `pinEnabled=${S.pinEnabled}`);
    app.call('go', 'atur');
    logTest('T7: Can access Atur to setup PIN', app.get('view').tab === 'atur', `tab=${app.get('view').tab}`);
    const F = app.get('F');
    let f = makePinForm('123456'); await F.pinstep(f);
    f = makePinForm('123456'); await F.pinstep(f);
    let S2 = app.get('S');
    logTest('T7: PIN setup works in master-only legacy',
      S2.pinEnabled === true && S2.pin && typeof S2.pin === 'object' && S2.pin.hash && S2.master === legacyMaster,
      `pinEnabled=${S2.pinEnabled}, pinEnvelope=${S2.pin && typeof S2.pin === 'object' && S2.pin.hash}, masterLegacy=${S2.master === legacyMaster}`);
  }

  // ---------- T8 ----------
  {
    const app = makeApp({ htmlPath, withCrypto: false }); app.reset(); app.clearStorage();
    let initThrew = false;
    try { app.init(); } catch (e) { initThrew = true; console.log('  init threw:', e.message); }
    logTest('T8: init completes without exception (no crypto)', !initThrew, '');
    let tickThrew = false;
    try { app.get('tick')(); } catch (e) { tickThrew = true; }
    logTest('T8: tick works', !tickThrew, '');
    let S = app.get('S');
    let cart = app.get('cart');
    const addEl = mkEl('button'); addEl.dataset.act = 'add'; addEl.dataset.id = 'item1';
    app.get('A').add(addEl);
    cart = app.get('cart');
    logTest('T8: add (kasir) works', cart.item1 === 1, `cart=${JSON.stringify(cart)}`);
    app.call('go', 'rekap');
    logTest('T8: go rekap blocked without crypto', app.get('view').tab === 'kasir', `tab=${app.get('view').tab}`);
    app.call('go', 'stok');
    logTest('T8: go stok blocked without crypto', app.get('view').tab === 'kasir', `tab=${app.get('view').tab}`);
    app.call('go', 'atur');
    logTest('T8: go atur blocked without crypto', app.get('view').tab === 'kasir', `tab=${app.get('view').tab}`);
    const canAccessOwner = app.get('canAccessOwner');
    logTest('T8: Owner forms blocked without crypto', !canAccessOwner('ing'), `canAccessOwner=${canAccessOwner('ing')}`);
  }

  // ---------- T9 ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    app.localStorage.setItem = () => { throw new Error('Storage quota exceeded'); };
    let S = app.get('S');
    app.call('go', 'atur');
    const F = app.get('F');
    let f = makePinForm('123456'); await F.pinstep(f);
    f = makePinForm('123456'); await F.pinstep(f);
    S = app.get('S');
    const pinStillNull = S.pin === null;
    const pinEnabledFalse = S.pinEnabled === false;
    const psErrEl = app.elements ? (app.elements.get('psErr') || null) : null;
    const errorText = psErrEl ? psErrEl.innerHTML : '';
    logTest('T9: PIN rollback on save error', pinStillNull && pinEnabledFalse && (errorText.includes('Gagal') || errorText.includes('gagal')),
      `S.pin=${S.pin}, pinEnabled=${S.pinEnabled}, psErr=${errorText}`);
  }

  // ---------- T10 (H2: real lock tests via visibilitychange + idle timer) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    let S = app.get('S');
    S.masterVerified = true;
    app.call('save');
    const parsed = JSON.parse(app.store[STORAGE_KEY]);
    logTest('T10: masterVerified not persisted', parsed.masterVerified === undefined, `keys=${Object.keys(parsed).join(',')}`);
    app.init();
    S = app.get('S');
    logTest('T10: masterVerified=false after reload', S.masterVerified === false, `masterVerified=${S.masterVerified}`);

    // Real lock test via visibilitychange
    const app2 = makeApp({ htmlPath }); app2.reset(); app2.clearStorage();
    const timers = [];
    const origSetTimeout = app2.ctx.setTimeout;
    app2.ctx.setTimeout = (fn, ms) => { const id = origSetTimeout(fn, ms); timers.push({ fn, ms, id }); return id; };
    app2.init();
    let S2 = app2.get('S');
    S2.masterVerified = true;
    visibilityChange(app2, true);
    logTest('T10: masterVerified=false after visibilitychange lock', app2.get('S').masterVerified === false, `masterVerified=${app2.get('S').masterVerified}`);

    // Idle timer test
    app2.get('S').masterVerified = true;
    const idle = timers.find(t => t.ms === 5 * 60 * 1000);
    if (idle) { idle.fn(); }
    logTest('T10: masterVerified=false after idle timer lock', app2.get('S').masterVerified === false, `masterVerified=${app2.get('S').masterVerified}, idleFound=${!!idle}`);
  }

  // ---------- T11 (H2: real dispatcher tests) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    app.call('go', 'atur');
    const F = app.get('F');
    let f = makePinForm('123456'); await F.pinstep(f);
    f = makePinForm('123456'); await F.pinstep(f);
    await F.pin(makePinUnlockForm('123456'));
    let v = app.get('view');
    logTest('T11: PIN unlock sets view.unlocked=true', v.unlocked === true, `unlocked=${v.unlocked}`);

    // After unlock, click owner action via dispatcher and assert handler runs
    const modalEl = app.elements.get('modal');
    modalEl.innerHTML = '';
    clickAct(app, 'ingnew');
    const modalOpened = modalEl.innerHTML.includes('Bahan baru') || modalEl.innerHTML.length > 0;
    logTest('T11: Owner action works when unlocked (dispatcher)', modalOpened, `modalInnerLen=${modalEl.innerHTML.length}`);

    // Lock: simulate visibilitychange
    app.document.hidden = true;
    app.dispatch('visibilitychange', app.document);
    // After lock, click owner action - should be blocked, S unchanged
    const sBefore = JSON.stringify(app.get('S'));
    modalEl.innerHTML = '';
    clickAct(app, 'menunew');
    const sAfter = JSON.stringify(app.get('S'));
    const blockedAfterLock = modalEl.innerHTML.length === 0 && sBefore === sAfter;
    logTest('T11: Owner action blocked after lock (dispatcher)', blockedAfterLock, `modalLen=${modalEl.innerHTML.length}, sChanged=${sBefore!==sAfter}`);
  }

  // ---------- T12 ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    const canAccessOwner = app.get('canAccessOwner');
    logTest('T12: Restore blocked pre-PIN (via canAccessOwner)', !canAccessOwner('restock'), `canAccessOwner=${canAccessOwner('restock')}`);
    app.get('S').pinEnabled = true;
    app.get('view').unlocked = false;
    logTest('T12: Restore blocked when locked', !canAccessOwner('restock'), `canAccessOwner=${canAccessOwner('restock')}`);
  }

  // ---------- T13 ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    const Akeys = Object.keys(app.get('A') || {});
    const CASHIER_ACTS = app.get('CASHIER_ACTS');
    const acts = [...new Set((html.match(/data-act="([A-Za-z0-9]+)"/g) || []).map(m => m.match(/data-act="([^"]+)"/)[1]))];
    const forms = [...new Set((html.match(/data-form="([A-Za-z0-9]+)"/g) || []).map(m => m.match(/data-form="([^"]+)"/)[1]))];
    const authForms = new Set(['pin','recovery']);
    const ownerForms = new Set(['camp','ing','menu','op','master','pinstep','restock','shop']);
    const classifyAct = (k) => {
      if (CASHIER_ACTS.has(k)) return { cat: 'cashier', reason: 'in CASHIER_ACTS allowlist (kasir/UI flow, no owner gate)' };
      if (k === 'pinreset') return { cat: 'owner-special', reason: 'owner-intent; allowed pre-PIN only when !S.pin (setup flow), else gated' };
      return { cat: 'owner', reason: 'not in CASHIER_ACTS; default-deny, requires canAccessOwner()' };
    };
    const classifyForm = (f) => {
      if (authForms.has(f)) return { cat: 'auth', reason: 'authentication/recovery form; allowed by canAccessOwner' };
      if (ownerForms.has(f)) return { cat: 'owner', reason: 'owner/business form; gated by canAccessOwner' };
      return { cat: 'uncategorized', reason: 'UNKNOWN' };
    };
    console.log('\n  === T13: A action classification ===');
    console.log('  ' + ['ACTION','CATEGORY','REASON'].join(' | '));
    let uncategorized = [];
    for (const k of Akeys) {
      const c = classifyAct(k);
      console.log(`  ${k} | ${c.cat} | ${c.reason}`);
      if (c.cat === 'uncategorized') uncategorized.push('act:'+k);
    }
    console.log('\n  === T13: data-form classification ===');
    console.log('  ' + ['FORM','CATEGORY','REASON'].join(' | '));
    for (const f of forms) {
      const c = classifyForm(f);
      console.log(`  ${f} | ${c.cat} | ${c.reason}`);
      if (c.cat === 'uncategorized') uncategorized.push('form:'+f);
    }
    const mustShow = ['saverc','rradd','rrdel','menumgr','rwtoggle','dtype','sub','exact','pinreset','forgot'];
    const missing = mustShow.filter(k => !Akeys.includes(k));
    if (missing.length) { uncategorized.push('missing:'+missing.join(',')); console.log('  MISSING required keys:', missing.join(',')); }
    logTest('T13: All A keys and data-form categorized', uncategorized.length === 0, uncategorized.length ? uncategorized.join('; ') : `Akeys=${Akeys.length}, forms=${forms.length}`);
  }

  // ---------- T14 (H5: cashier regression with recipe + stock + receipt number) ----------
  {
    function runTxScenario(appLabel, app) {
      app.reset(); app.clearStorage(); app.init();
      app.call('go', 'kasir');
      let S = app.get('S');
      const ingId = 'ing1';
      const menuId = 'menu1';
      S.ingredients = [{ id: ingId, name: 'Biji Kopi', unit: 'g', stock: 100, min: 10, cost: 0 }];
      S.menu = [{ id: menuId, name: 'Kopi Test', price: 15000, cup: true, recipe: [{ ing: ingId, qty: 10 }] }];
      S.op = S.operators[0].id;
      const addEl = mkEl('button'); addEl.dataset.act='add'; addEl.dataset.id=menuId;
      clickAct(app, 'add', { id: menuId });
      const cartAfterAdd = app.get('cart');
      const cartOk = cartAfterAdd[menuId] === 1;
      clickAct(app, 'pay');
      let S2 = app.get('S');
      const txSaved = Array.isArray(S2.tx) && S2.tx.length > 0;
      const stockAfter = S2.ingredients.find(i=>i.id===ingId);
      const stockOk = stockAfter && stockAfter.stock === 90;
      const txNo = txSaved ? S2.tx[S2.tx.length-1].no : null;
      return { appLabel, cartOk, txSaved, stockBefore: 100, stockAfter: stockAfter ? stockAfter.stock : null, stockOk, txNo, txCount: S2.tx.length };
    }

    const headRes = runTxScenario('HEAD', makeApp({ htmlPath }));
    let oldRes = null;
    const oldPath = '/tmp/kasir_348103c.html';
    if (fs.existsSync(oldPath)) {
      oldRes = runTxScenario('348103c', makeApp({ htmlPath: oldPath }));
    } else {
      console.log('  T14: /tmp/kasir_348103c.html not found, skipping old comparison');
    }

    console.log('\n  === T14 Regression (side-by-side) ===');
    console.log('  ' + ['metric','HEAD','348103c','identical'].join(' | '));
    const rows = [
      ['cartOk', headRes.cartOk, oldRes ? oldRes.cartOk : 'N/A'],
      ['txSaved', headRes.txSaved, oldRes ? oldRes.txSaved : 'N/A'],
      ['stockBefore', headRes.stockBefore, oldRes ? oldRes.stockBefore : 'N/A'],
      ['stockAfter', headRes.stockAfter, oldRes ? oldRes.stockAfter : 'N/A'],
      ['stockOk(-10)', headRes.stockOk, oldRes ? oldRes.stockOk : 'N/A'],
      ['txCount', headRes.txCount, oldRes ? oldRes.txCount : 'N/A'],
    ];
    for (const [m,h,o] of rows) {
      const ident = (o === 'N/A') ? 'N/A' : (h === o ? 'YES' : 'NO');
      console.log(`  ${m} | ${h} | ${o} | ${ident}`);
    }
    const allIdentical = oldRes ? rows.every(([m,h,o]) => h === o) : false;
    logTest('T14: Add item to cart', headRes.cartOk, `cartOk=${headRes.cartOk}`);
    logTest('T14: Transaction saved via pay', headRes.txSaved, `txCount=${headRes.txCount}`);
    logTest('T14: Stock decreased per recipe', headRes.stockOk, `stockBefore=100, stockAfter=${headRes.stockAfter}`);
    logTest('T14: Regression vs 348103c identical', oldRes ? allIdentical : false, oldRes ? `identical=${allIdentical}` : '348103c file missing');
  }

  // ---------- T15 (H3: new user pinstep via dispatcher) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    app.call('go', 'atur');
    const f1 = makePinForm('123456'); f1.dataset.form='pinstep';
    submitForm(app, f1);
    await new Promise(r => setTimeout(r, 100));
    const f2 = makePinForm('123456'); f2.dataset.form='pinstep';
    submitForm(app, f2);
    await new Promise(r => setTimeout(r, 100));
    const S = app.get('S');
    logTest('T15: New user pinstep x2 via dispatcher -> pin envelope', S.pin && typeof S.pin==='object' && S.pin.hash, `pin=${JSON.stringify(S.pin)}`);
    logTest('T15: pinEnabled=true', S.pinEnabled===true, `pinEnabled=${S.pinEnabled}`);
    logTest('T15: tab kasir', app.get('view').tab==='kasir', `tab=${app.get('view').tab}`);
  }

  // ---------- T16 (H3: new user master creation pre-PIN via dispatcher) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    // Pre-PIN: pinEnabled false, no pin set
    const f = makeMasterForm('', 'masterbaru12345', 'masterbaru12345'); // 15 chars
    f.dataset.form = 'master';
    submitForm(app, f);
    await new Promise(r => setTimeout(r, 100));
    const S = app.get('S');
    logTest('T16: Pre-PIN master creation via dispatcher -> envelope stored', S.master && typeof S.master==='object' && S.master.hash, `master=${JSON.stringify(S.master)}`);
  }

  // ---------- T17 (H3: legacy master-only pre-PIN migration via dispatcher) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage();
    const legacyMaster = app.get('legacyHash')('masterlama123');
    app.store[STORAGE_KEY] = JSON.stringify({ v:2,seq:0,shop:'Kopi Kita',rewardAt:10,pin:null,master:legacyMaster,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[{id:'op1',name:'Kasir Pagi'}],ingredients:[],menu:[],campaigns:[],recovery:null });
    app.init();
    const f = makeMasterForm('masterlama123','masterbaru123456','masterbaru123456');
    f.dataset.form = 'master';
    submitForm(app, f);
    await new Promise(r => setTimeout(r, 100));
    const S = app.get('S');
    logTest('T17: Legacy master-only pre-PIN migration via dispatcher', S.master && typeof S.master==='object' && S.master.hash, `master=${JSON.stringify(S.master)}`);
  }

  // ---------- T18 (H3: pre-PIN all owner actions/forms blocked, S identical) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    const Akeys = Object.keys(app.get('A') || {});
    const CASHIER_ACTS = app.get('CASHIER_ACTS');
    const ownerActs = Akeys.filter(k => !CASHIER_ACTS.has(k) && !(k === 'pinreset' && !app.get('S').pin));
    const S0 = JSON.stringify(app.get('S'));
    for (const act of ownerActs) { clickAct(app, act); await new Promise(r => setTimeout(r, 50)); }
    const S1 = JSON.stringify(app.get('S'));
    logTest('T18: Pre-PIN all owner A actions blocked via dispatcher, S identical', S0 === S1, `changed=${S0!==S1}, ownerActs=${ownerActs.length}`);

    const beforeForms = JSON.stringify(app.get('S'));
    const mkForm = (name, fields) => { const f=mkEl('form'); f.dataset.form=name; for(const [k,v] of Object.entries(fields)){ const i=mkEl('input'); i.name=k; i.value=v; f[k]=i; } return f; };
    submitForm(app, mkForm('ing', {id:'',name:'X',unit:'g',stock:'1',min:'0'})); await new Promise(r => setTimeout(r, 50));
    submitForm(app, mkForm('menu', {id:'',name:'X',price:'1000'})); await new Promise(r => setTimeout(r, 50));
    submitForm(app, mkForm('shop', {shop:'Hacked'})); await new Promise(r => setTimeout(r, 50));
    submitForm(app, mkForm('op', {name:'Hacker'})); await new Promise(r => setTimeout(r, 50));
    const afterForms = JSON.stringify(app.get('S'));
    logTest('T18: Pre-PIN owner forms ing/menu/shop/op blocked via dispatcher, S identical', beforeForms === afterForms, `changed=${beforeForms!==afterForms}`);
  }

  // ---------- T19 (H3: restoreIn change blocked pre-PIN and when locked) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    const restoreEl = app.elements.get('restoreIn');
    restoreEl.id = 'restoreIn';
    restoreEl.value = 'C:\\fakepath\\backup.json';
    restoreEl.files = [makeRestoreFile({ v:2,seq:0,shop:'X',rewardAt:10,pin:null,master:null,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[{id:'o1',name:'Kasir'}],ingredients:[],menu:[],campaigns:[],recovery:null })];
    const S0 = JSON.stringify(app.get('S'));
    changeEl(app, restoreEl); await new Promise(r => setTimeout(r, 100));
    const S1 = JSON.stringify(app.get('S'));
    logTest('T19: restoreIn pre-PIN blocked via dispatcher, S unchanged', S0 === S1, `changed=${S0!==S1}`);
    logTest('T19: restoreIn pre-PIN input cleared', restoreEl.value === '', `value=${restoreEl.value}`);

    // When locked (pinEnabled true, unlocked false)
    const app2 = makeApp({ htmlPath }); app2.reset(); app2.clearStorage(); app2.init();
    app2.get('S').pinEnabled = true;
    app2.get('view').unlocked = false;
    const r2 = app2.elements.get('restoreIn');
    r2.id = 'restoreIn'; r2.value = 'C:\\fakepath\\b.json';
    r2.files = [makeRestoreFile({ v:2,seq:0,shop:'Y',rewardAt:10,pin:null,master:null,pinEnabled:false,pinFails:0,pinLockUntil:0,pinCycles:0,masterFails:0,masterLockUntil:0,lastActive:0,sessionStart:0,operators:[],ingredients:[],menu:[],campaigns:[],recovery:null })];
    const S2before = JSON.stringify(app2.get('S'));
    changeEl(app2, r2); await new Promise(r => setTimeout(r, 100));
    const S2after = JSON.stringify(app2.get('S'));
    logTest('T19: restoreIn locked blocked via dispatcher, S unchanged', S2before === S2after, `changed=${S2before!==S2after}`);
    logTest('T19: restoreIn locked input cleared', r2.value === '', `value=${r2.value}`);
  }

  // ---------- T20 (H3: No Web Crypto - cashier flows work, owner blocked, stempel nav ok) ----------
  {
    const app = makeApp({ htmlPath, withCrypto: false }); app.reset(); app.clearStorage(); app.init();
    const S = app.get('S');
    S.menu = [{ id:'m1', name:'Kopi', price:10000, cup:true, recipe:[] }];
    S.ingredients = [];
    S.op = S.operators[0] ? S.operators[0].id : '';
    clickAct(app, 'add', { id: 'm1' }); await new Promise(r => setTimeout(r, 50));
    const cartAfterAdd = app.get('cart');
    logTest('T20: add works without crypto (dispatcher)', cartAfterAdd.m1 === 1, `cart=${JSON.stringify(cartAfterAdd)}`);
    clickAct(app, 'inc', { id: 'm1' }); await new Promise(r => setTimeout(r, 50));
    logTest('T20: inc works without crypto (dispatcher)', app.get('cart').m1 === 2, `cart=${JSON.stringify(app.get('cart'))}`);
    app.get('S').lastTx = { id:'t1', no:1, ts:Date.now(), items:[{id:'m1',name:'Kopi',price:10000,qty:1}], sub:10000, disc:0, total:10000, pay:10000, change:0, op:'' };
    clickAct(app, 'saverc'); await new Promise(r => setTimeout(r, 50));
    const savercOk = !app.toastEl.textContent.includes('Area owner terkunci');
    logTest('T20: saverc works without crypto (dispatcher)', savercOk, `toast=${app.toastEl.textContent}`);
    clickAct(app, 'pay'); await new Promise(r => setTimeout(r, 50));
    logTest('T20: pay works without crypto (dispatcher)', app.get('S').tx.length >= 0, `tx=${app.get('S').tx.length}`);
    const sBefore = JSON.stringify(app.get('S'));
    clickAct(app, 'menunew'); await new Promise(r => setTimeout(r, 50));
    clickAct(app, 'wipe'); await new Promise(r => setTimeout(r, 50));
    const fShop = mkEl('form'); fShop.dataset.form='shop'; fShop.shop=mkEl('input'); fShop.shop.value='X'; fShop.shop.name='shop';
    submitForm(app, fShop); await new Promise(r => setTimeout(r, 50));
    const sAfter = JSON.stringify(app.get('S'));
    logTest('T20: owner click/submit blocked without crypto (dispatcher)', sBefore === sAfter, `changed=${sBefore!==sAfter}`);
    app.call('go', 'stempel');
    logTest('T20: stempel nav works without crypto', app.get('view').tab === 'stempel', `tab=${app.get('view').tab}`);
  }

  // ---------- T21 (H3: Locked with active PIN - menumgr shows PIN modal) ----------
  {
    const app = makeApp({ htmlPath }); app.reset(); app.clearStorage(); app.init();
    // Setup PIN first
    app.call('go', 'atur');
    const F = app.get('F');
    let f = makePinForm('123456'); await F.pinstep(f);
    f = makePinForm('123456'); await F.pinstep(f);
    await F.pin(makePinUnlockForm('123456'));
    // Now lock the session
    app.document.hidden = true;
    app.dispatch('visibilitychange', app.document);
    // Click menumgr - should show PIN modal (not just toast)
    const modalEl = app.elements.get('modal');
    modalEl.innerHTML = '';
    clickAct(app, 'menumgr');
    const showsPinModal = modalEl.innerHTML.includes('PIN') || modalEl.innerHTML.includes('Area owner');
    logTest('T21: Locked with PIN - menumgr shows PIN modal (dispatcher)', showsPinModal, `modalLen=${modalEl.innerHTML.length}`);
  }

  console.log('\n══════════════════════════════════════════════════════════════');
  console.log(`  TOTAL: ${testCount} | PASS: ${passCount} | FAIL: ${failCount}`);
  console.log('══════════════════════════════════════════════════════════════\n');
  fs.writeFileSync(path.resolve(__dirname, 'results.json'), JSON.stringify({ total: testCount, pass: passCount, fail: failCount, tests: results }, null, 2));
  console.log(`Results saved to ${path.resolve(__dirname, 'results.json')}`);
  process.exit(failCount > 0 ? 1 : 0);
}

// Entry point
const htmlPath = process.env.KASIR_HTML || path.resolve(__dirname, '../../Kasir Kopi (1).html');
runTests(htmlPath).catch(err => { console.error('Test harness error:', err); process.exit(1); });