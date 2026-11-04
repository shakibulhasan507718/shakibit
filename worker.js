/* ============================================================
   shakibit.online — Cloudflare Worker (সব সিকিউর কাজ এখানে)
   Secrets : SERVICE_ACCOUNT_JSON , SESSION_SECRET
   Vars    : FIREBASE_PROJECT_ID , ALLOWED_ORIGINS , SITE_URL
   ============================================================ */
class AppErr extends Error {
  constructor(msg, code, status, extra){ super(msg); this.code = code || 'err'; this.status = status || 400; this.extra = extra || null; }
}
const PBKDF2_ITER = 100000;
const CATS = { bangla: 'বাংলা', desi: 'দেশি', boyboy: 'ছেলে ছেলে', mixed: 'পাঁচ মিশালী', other: 'অন্যান্য' };
const TXT = new TextEncoder(), TXD = new TextDecoder();
const UN_RE = /^[a-z][a-z0-9_.]{2,19}$/;
const bn = n => String(n).replace(/\d/g, d => '০১২৩৪৫৬৭৮৯'[d]);
const money = n => '৳' + bn(Math.round((+n || 0) * 100) / 100);
const r2 = n => Math.round((+n || 0) * 100) / 100;

/* ---------- base64url / token ---------- */
const B64 = {
  enc(buf){ const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  dec(str){ str = String(str).replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; const bin = atob(str), a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; },
  str(s){ return B64.enc(TXT.encode(s)); }
};
async function hmacKey(secret){ return crypto.subtle.importKey('raw', TXT.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']); }
async function signTok(env, obj){
  if (!env.SESSION_SECRET) throw new Error('SESSION_SECRET missing');
  const p = B64.str(JSON.stringify(obj)), k = await hmacKey(env.SESSION_SECRET);
  return p + '.' + B64.enc(await crypto.subtle.sign('HMAC', k, TXT.encode(p)));
}
async function verifyTok(env, tok){
  if (!tok || tok.indexOf('.') < 1) return null;
  const i = tok.indexOf('.'), p = tok.slice(0, i), s = tok.slice(i + 1);
  try {
    const k = await hmacKey(env.SESSION_SECRET);
    if (!(await crypto.subtle.verify('HMAC', k, B64.dec(s), TXT.encode(p)))) return null;
    const o = JSON.parse(TXD.decode(B64.dec(p)));
    if (o.e && o.e < Date.now()) return null;
    return o;
  } catch (e) { return null; }
}
async function sha256hex(s){ const h = new Uint8Array(await crypto.subtle.digest('SHA-256', TXT.encode(s))); return Array.from(h).map(x => x.toString(16).padStart(2, '0')).join(''); }
function rndHex(n){ const a = crypto.getRandomValues(new Uint8Array(n)); return Array.from(a).map(x => x.toString(16).padStart(2, '0')).join(''); }

/* ---------- পাসওয়ার্ড হ্যাশ (PBKDF2-SHA256, প্রতি ইউজারের আলাদা salt) ---------- */
async function hashPw(pw, saltB64, iter){
  const k = await crypto.subtle.importKey('raw', TXT.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return B64.enc(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: B64.dec(saltB64), iterations: iter }, k, 256));
}
function safeEq(a, b){ a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
async function newCred(pw){ const salt = B64.enc(crypto.getRandomValues(new Uint8Array(16))); return { salt, hash: await hashPw(pw, salt, PBKDF2_ITER), iter: PBKDF2_ITER }; }

/* ---------- Bot Token এনক্রিপশন (AES-GCM) ---------- */
async function aesKey(env){ const h = await crypto.subtle.digest('SHA-256', TXT.encode('botkey|' + env.SESSION_SECRET)); return crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['encrypt', 'decrypt']); }
async function encTok(env, t){ const iv = crypto.getRandomValues(new Uint8Array(12)); const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), TXT.encode(t)); return B64.enc(iv) + '.' + B64.enc(c); }
async function decTok(env, s){ const [i, c] = String(s).split('.'); return TXD.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: B64.dec(i) }, await aesKey(env), B64.dec(c))); }

/* ---------- Firestore REST (সার্ভিস অ্যাকাউন্ট) ---------- */
let _gt = { t: '', e: 0 };
async function gToken(env){
  if (_gt.t && _gt.e > Date.now() + 60000) return _gt.t;
  const sa = JSON.parse(env.SERVICE_ACCOUNT_JSON), now = Math.floor(Date.now() / 1000);
  const head = B64.str(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = B64.str(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = B64.enc(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, TXT.encode(head + '.' + claim)));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + head + '.' + claim + '.' + sig });
  const j = await r.json();
  if (!j.access_token) throw new Error('Google token error: ' + JSON.stringify(j));
  _gt = { t: j.access_token, e: Date.now() + (j.expires_in || 3600) * 1000 };
  return _gt.t;
}
const FSB = env => 'https://firestore.googleapis.com/v1/projects/' + env.FIREBASE_PROJECT_ID + '/databases/(default)/documents';
const DOCN = (env, p) => 'projects/' + env.FIREBASE_PROJECT_ID + '/databases/(default)/documents/' + p;
function toV(v){
  if (v === null || v === undefined) return { nullValue: null };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === 'string') return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toV) } };
  return { mapValue: { fields: toF(v) } };
}
function toF(o){ const f = {}; for (const k in o) if (o[k] !== undefined) f[k] = toV(o[k]); return f; }
function fromV(v){
  if ('nullValue' in v) return null; if ('booleanValue' in v) return v.booleanValue;
  if ('integerValue' in v) return Number(v.integerValue); if ('doubleValue' in v) return v.doubleValue;
  if ('stringValue' in v) return v.stringValue; if ('timestampValue' in v) return new Date(v.timestampValue);
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromV);
  if ('mapValue' in v) return fromF(v.mapValue.fields || {});
  return null;
}
function fromF(f){ const o = {}; for (const k in f) o[k] = fromV(f[k]); return o; }
async function fsReq(env, method, url, body){
  const t = await gToken(env);
  const r = await fetch(url, { method, headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const txt = await r.text(); let j = {}; try { j = JSON.parse(txt); } catch (e) {}
  if (!r.ok) { const e = new Error((j.error && j.error.message) || ('Firestore ' + r.status)); e.status = r.status; e.fsStatus = j.error && j.error.status; throw e; }
  return j;
}
async function getDoc(env, path, tx){
  try {
    const j = await fsReq(env, 'GET', FSB(env) + '/' + path + (tx ? '?transaction=' + encodeURIComponent(tx) : ''));
    return { id: path.split('/').pop(), path, exists: true, data: fromF(j.fields || {}) };
  } catch (e) { if (e.status === 404) return { id: path.split('/').pop(), path, exists: false, data: null }; throw e; }
}
async function query(env, coll, filters, o){
  o = o || {};
  const sq = { from: [{ collectionId: coll }] };
  if (filters && filters.length) {
    const fl = filters.map(f => ({ fieldFilter: { field: { fieldPath: f[0] }, op: f[1] || 'EQUAL', value: toV(f[2]) } }));
    sq.where = fl.length === 1 ? fl[0] : { compositeFilter: { op: 'AND', filters: fl } };
  }
  if (o.order) sq.orderBy = [{ field: { fieldPath: o.order }, direction: o.desc ? 'DESCENDING' : 'ASCENDING' }];
  if (o.limit) sq.limit = o.limit;
  const rows = await fsReq(env, 'POST', FSB(env) + (o.parent ? '/' + o.parent : '') + ':runQuery', { structuredQuery: sq });
  return rows.filter(r => r.document).map(r => ({ id: r.document.name.split('/').pop(), path: r.document.name.split('/documents/')[1], data: fromF(r.document.fields || {}) }));
}
/* write builders */
const W = {
  set: (env, p, data, pre) => Object.assign({ update: { name: DOCN(env, p), fields: toF(data) } }, pre ? { currentDocument: pre } : {}),
  upd: (env, p, data, del) => ({ update: { name: DOCN(env, p), fields: toF(data) }, updateMask: { fieldPaths: Object.keys(data).filter(k => data[k] !== undefined).concat(del || []) }, currentDocument: { exists: true } }),
  merge: (env, p, data) => ({ update: { name: DOCN(env, p), fields: toF(data) }, updateMask: { fieldPaths: Object.keys(data).filter(k => data[k] !== undefined) } }),
  del: (env, p) => ({ delete: DOCN(env, p) })
};
async function commit(env, writes){ for (let i = 0; i < writes.length; i += 400) await fsReq(env, 'POST', FSB(env) + ':commit', { writes: writes.slice(i, i + 400) }); }
async function runTx(env, fn){
  for (let a = 0; a < 4; a++) {
    const b = await fsReq(env, 'POST', FSB(env) + ':beginTransaction', { options: { readWrite: {} } });
    const tx = b.transaction;
    try {
      const writes = await fn(tx);
      if (writes && writes.length) await fsReq(env, 'POST', FSB(env) + ':commit', { writes, transaction: tx });
      else await fsReq(env, 'POST', FSB(env) + ':rollback', { transaction: tx }).catch(() => {});
      return;
    } catch (e) {
      if (!(e instanceof AppErr) && e.fsStatus === 'ABORTED' && a < 3) continue;
      if (e instanceof AppErr) await fsReq(env, 'POST', FSB(env) + ':rollback', { transaction: tx }).catch(() => {});
      throw e;
    }
  }
}

/* ---------- CORS / রেসপন্স ---------- */
const allowList = env => String(env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
function corsHeaders(env, req){
  const o = req.headers.get('Origin') || '', al = allowList(env);
  const a = al.includes('*') ? '*' : (al.includes(o) ? o : al[0]);
  return { 'Access-Control-Allow-Origin': a, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Max-Age': '86400', 'Vary': 'Origin' };
}
const json = (o, status, h) => new Response(JSON.stringify(o), { status: status || 200, headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, h || {}) });

/* ---------- হেল্পার ---------- */
const cleanStr = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f]/g, ' ').trim().replace(/\s+/g, ' ').slice(0, n);
const cleanId = s => String(s || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 80);
const tms = d => (d instanceof Date ? d.getTime() : 0);
const dayKeyBD = () => new Date(Date.now() + 6 * 3600 * 1000).toISOString().slice(0, 10).replace(/-/g, '');
function normLink(u){ return String(u || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/^telegram\.me\//, 't.me/').replace(/[?#].*$/, '').replace(/\/+$/, ''); }
const isHttp = u => /^https?:\/\/[^\s]+$/i.test(String(u || '').trim());
const effPrice = d => { const p = +d.price || 0, f = +d.offerPrice || 0; return (f > 0 && f < p) ? f : p; };
const getSettings = async env => (await getDoc(env, 'settings/site')).data || {};
const siteUrl = env => env.SITE_URL || 'https://shakibit.online/';

/* ---------- অথেন্টিকেশন ---------- */
async function needUser(env, req){
  const tok = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const o = await verifyTok(env, tok);
  if (!o || o.k !== 's' || !o.u) throw new AppErr('আবার লগইন করুন', 'auth', 401);
  const u = await getDoc(env, 'users/' + o.u);
  if (!u.exists) throw new AppErr('আবার লগইন করুন', 'auth', 401);
  if (u.data.blocked) throw blockedErr(u.data);
  return { uid: o.u, user: u.data };
}
function blockedErr(u){ return new AppErr('আপনার একাউন্ট ব্লক করা হয়েছে', 'blocked', 403, { blocked: { name: u.name || '', username: u.username || '', reason: u.blockReason || '' } }); }
let _jwks = { k: null, e: 0 };
async function needAdmin(env, req){
  const tok = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const parts = tok.split('.'), bad = () => new AppErr('অ্যাডমিন অনুমতি নেই', 'admin', 401);
  if (parts.length !== 3) throw bad();
  let head, pay;
  try { head = JSON.parse(TXD.decode(B64.dec(parts[0]))); pay = JSON.parse(TXD.decode(B64.dec(parts[1]))); } catch (e) { throw bad(); }
  if (head.alg !== 'RS256' || !head.kid) throw bad();
  if (!_jwks.k || _jwks.e < Date.now()) {
    const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
    _jwks = { k: (await r.json()).keys || [], e: Date.now() + 3600000 };
  }
  const jwk = _jwks.k.find(k => k.kid === head.kid); if (!jwk) throw bad();
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, B64.dec(parts[2]), TXT.encode(parts[0] + '.' + parts[1]));
  const pid = env.FIREBASE_PROJECT_ID;
  if (!ok || pay.aud !== pid || pay.iss !== 'https://securetoken.google.com/' + pid || !pay.sub || (pay.exp || 0) * 1000 < Date.now()) throw bad();
  const a = await getDoc(env, 'admins/' + pay.sub);
  if (!a.exists) throw bad();
  return { uid: pay.sub, email: pay.email || '' };
}

/* ---------- বিজ্ঞাপন গেট (৩ ধাপ) ---------- */
function gateInfo(set){
  const V = set.verify || {}, urls = [V.url1, V.url2, V.url3].filter(isHttp);
  return { on: V.enabled !== false && urls.length > 0, steps: urls.length, secs: Math.max(1, +V.seconds || 5) };
}
async function checkGate(env, set, pass, scope){
  if (!gateInfo(set).on) return;
  const o = await verifyTok(env, pass);
  if (!o || o.k !== 'pass' || o.s !== scope) throw new AppErr('আগে বিজ্ঞাপন ভেরিফাই সম্পন্ন করুন', 'gate', 403);
}
async function hGateStart(env, req, b){
  const scope = cleanId(b.scope); if (!scope) throw new AppErr('ভুল অনুরোধ');
  return { token: await signTok(env, { k: 'gs', s: scope, t: Date.now(), e: Date.now() + 30 * 60000 }) };
}
async function hGateFinish(env, req, b){
  const o = await verifyTok(env, String(b.token || ''));
  if (!o || o.k !== 'gs') throw new AppErr('ভেরিফাই সেশন মেয়াদোত্তীর্ণ, আবার শুরু করুন', 'gate');
  const g = gateInfo(await getSettings(env));
  if (g.on && Date.now() - o.t < Math.max(0, g.steps * g.secs - 3) * 1000) throw new AppErr('প্রতিটি ধাপের সময় পর্যন্ত অপেক্ষা করুন', 'gate');
  return { pass: await signTok(env, { k: 'pass', s: o.s, e: Date.now() + 5 * 3600 * 1000 }) };
}

/* ---------- রেজিস্ট্রেশন / লগইন ---------- */
const sessionTok = (env, uid) => signTok(env, { k: 's', u: uid, e: Date.now() + 30 * 86400000 });
const profileOf = (uid, u) => ({ uid, name: u.name || '', username: u.username || '', balance: +u.balance || 0 });
function checkUn(un){ if (!UN_RE.test(un)) throw new AppErr('Username ৩-২০ অক্ষরের হতে হবে; ইংরেজি ছোট অক্ষর দিয়ে শুরু, শুধু a-z, 0-9, _ ও . চলবে'); }
async function hRegister(env, req, b){
  const name = cleanStr(b.name, 60), un = String(b.username || '').trim().toLowerCase(), pw = String(b.password || ''), cf = String(b.confirm || '');
  if (name.length < 2) throw new AppErr('আপনার নাম লিখুন (কমপক্ষে ২ অক্ষর)');
  checkUn(un);
  if (pw.length < 6) throw new AppErr('Password কমপক্ষে ৬ অক্ষরের হতে হবে');
  if (pw.length > 100) throw new AppErr('Password অনেক বড়');
  if (pw !== cf) throw new AppErr('Password ও Confirm Password মিলছে না');
  const uid = rndHex(16), cred = await newCred(pw);
  try {
    await commit(env, [
      W.set(env, 'usernames/' + un, { uid }, { exists: false }),
      W.set(env, 'users/' + uid, { name, username: un, balance: 0, createdAt: new Date() }),
      W.set(env, 'credentials/' + uid, cred)
    ]);
  } catch (e) {
    if (e.fsStatus === 'ALREADY_EXISTS' || e.fsStatus === 'FAILED_PRECONDITION') throw new AppErr('এই Username আগেই নেওয়া হয়েছে, অন্য Username দিন', 'dupuser');
    throw e;
  }
  return { token: await sessionTok(env, uid), profile: { uid, name, username: un, balance: 0 } };
}
async function hLogin(env, req, b){
  const un = String(b.username || '').trim().toLowerCase(), pw = String(b.password || '');
  const bad = new AppErr('Username বা Password ভুল', 'login', 401);
  if (!un || !pw || un.length > 40 || pw.length > 100) throw bad;
  const ud = await getDoc(env, 'usernames/' + un); if (!ud.exists) throw bad;
  const uid = ud.data.uid, cd = await getDoc(env, 'credentials/' + uid); if (!cd.exists) throw bad;
  const c = cd.data;
  if (c.lockUntil && tms(c.lockUntil) > Date.now()) throw new AppErr('অনেকবার ভুল চেষ্টা হয়েছে, কিছুক্ষণ পর আবার চেষ্টা করুন', 'locked', 429);
  const h = await hashPw(pw, c.salt, c.iter || PBKDF2_ITER);
  if (!safeEq(h, c.hash)) {
    const f = (+c.fails || 0) + 1;
    await commit(env, [W.upd(env, 'credentials/' + uid, f >= 8 ? { fails: 0, lockUntil: new Date(Date.now() + 10 * 60000) } : { fails: f })]).catch(() => {});
    throw bad;
  }
  if (c.fails) await commit(env, [W.upd(env, 'credentials/' + uid, { fails: 0 })]).catch(() => {});
  const u = await getDoc(env, 'users/' + uid); if (!u.exists) throw bad;
  if (u.data.blocked) throw blockedErr(u.data);
  return { token: await sessionTok(env, uid), profile: profileOf(uid, u.data) };
}
async function hMe(env, req){
  const { uid, user } = await needUser(env, req);
  const [notes, chat, set, cnt] = await Promise.all([
    query(env, 'notifications', [['to', 'EQUAL', uid]], { limit: 50 }),
    getDoc(env, 'chats/' + uid),
    getSettings(env),
    getDoc(env, 'dailyCounts/' + uid + '_' + dayKeyBD())
  ]);
  const limit = Math.max(1, parseInt(set.dailyLimit) || 10), used = cnt.exists ? (+cnt.data.n || 0) : 0;
  return {
    profile: profileOf(uid, user),
    notes: notes.map(n => ({ title: n.data.title || '', body: n.data.body || '', at: tms(n.data.at) })).sort((a, b) => b.at - a.at).slice(0, 30),
    chatUnread: !!(chat.exists && chat.data.unreadUser),
    dailyLeft: Math.max(0, limit - used)
  };
}

/* ---------- VIP লিংক জমা ---------- */
async function hSubmit(env, req, b){
  const { uid, user } = await needUser(env, req);
  const set = await getSettings(env);
  await checkGate(env, set, b.pass, 'vip');
  const gname = cleanStr(b.groupName, 80), gtype = String(b.groupType || ''), cat = String(b.category || ''), link = String(b.link || '').trim();
  if (gname.length < 2) throw new AppErr('গ্রুপের নাম লিখুন');
  if (gtype !== 'private' && gtype !== 'public') throw new AppErr('গ্রুপ টাইপ বেছে নিন');
  if (!CATS[cat]) throw new AppErr('গ্রুপের ধরন বেছে নিন');
  const price = r2((set.linkPrices || {})[cat]);
  if (!(price > 0)) throw new AppErr('এই ক্যাটাগরির মূল্য এখনো নির্ধারণ করা হয়নি, অ্যাডমিনকে জানান', 'noprice');
  if (!isHttp(link) || link.length > 500) throw new AppErr('লিংক সঠিক নয় — https:// দিয়ে শুরু হওয়া Valid লিংক দিন');
  const norm = normLink(link), key = await sha256hex(norm), DUP = 'এই লিংক ইতিমধ্যেই আছে। অনুগ্রহ করে অন্য লিংক ব্যবহার করুন।';
  if ((await query(env, 'freeLinks', [['norm', 'EQUAL', norm]], { limit: 1 })).length) throw new AppErr(DUP, 'dup');
  const limit = Math.max(1, parseInt(set.dailyLimit) || 10), day = dayKeyBD(), rid = 'LR' + Date.now().toString(36).toUpperCase() + rndHex(3).toUpperCase();
  await runTx(env, async tx => {
    const cnt = await getDoc(env, 'dailyCounts/' + uid + '_' + day, tx), n = cnt.exists ? (+cnt.data.n || 0) : 0;
    if (n >= limit) throw new AppErr('আজকের সর্বোচ্চ ' + bn(limit) + 'টি লিংকের সীমা শেষ। আগামীকাল আবার চেষ্টা করুন।', 'limit');
    const kd = await getDoc(env, 'linkKeys/' + key, tx);
    if (kd.exists) throw new AppErr(DUP, 'dup');
    return [
      W.set(env, 'linkKeys/' + key, { rid, uid, at: new Date() }),
      W.set(env, 'linkRequests/' + rid, { uid, name: user.name || '', username: user.username || '', groupName: gname, groupType: gtype, category: cat, categoryLabel: CATS[cat], price, link, norm, status: 'pending', at: new Date() }),
      cnt.exists ? W.upd(env, 'dailyCounts/' + uid + '_' + day, { n: n + 1 }) : W.set(env, 'dailyCounts/' + uid + '_' + day, { uid, day, n: 1 })
    ];
  });
  return { reqNo: rid };
}

/* ---------- উইথড্র / হিস্ট্রি ---------- */
async function hWdRequest(env, req, b){
  const { uid, user } = await needUser(env, req);
  const set = await getSettings(env), minW = +((set.payment || {}).minWithdraw) || 50;
  const method = String(b.method || ''), number = String(b.number || '').replace(/\D/g, ''), amount = r2(b.amount);
  if (method !== 'bKash' && method !== 'Nagad') throw new AppErr('মাধ্যম বেছে নিন');
  if (!/^01[3-9]\d{8}$/.test(number)) throw new AppErr('সঠিক মোবাইল নম্বর দিন (01XXXXXXXXX)');
  if (!(amount >= minW)) throw new AppErr('ন্যূনতম উইথড্র ' + money(minW));
  const wid = 'W' + Date.now().toString(36).toUpperCase() + rndHex(3).toUpperCase();
  await runTx(env, async tx => {
    const u = await getDoc(env, 'users/' + uid, tx), bal = +(u.data || {}).balance || 0;
    if (bal < amount) throw new AppErr('ব্যালেন্স কম', 'low-balance');
    return [
      W.upd(env, 'users/' + uid, { balance: r2(bal - amount) }),
      W.set(env, 'withdrawals/' + wid, { uid, name: user.name || '', username: user.username || '', method, number, amount, status: 'pending', at: new Date() })
    ];
  });
  return {};
}
async function hHistory(env, req){
  const { uid } = await needUser(env, req);
  const [w, t, l, p] = await Promise.all(['withdrawals', 'transactions', 'linkRequests', 'purchases'].map(c => query(env, c, [['uid', 'EQUAL', uid]], { limit: 200 })));
  const fmt = (rows, f) => rows.map(r => Object.assign({ id: r.id, at: tms(r.data.at) }, f(r.data))).sort((a, b) => b.at - a.at).slice(0, 60);
  return {
    withdrawals: fmt(w, d => ({ amount: d.amount, method: d.method, number: d.number, status: d.status, reason: d.reason || '', trxId: d.trxId || '', fee: d.fee || 0 })),
    transactions: fmt(t, d => ({ type: d.type, kind: d.kind, amount: d.amount, title: d.title || '' })),
    links: fmt(l, d => ({ groupName: d.groupName, price: d.price, status: d.status, reason: d.reason || '', category: d.categoryLabel || '' })),
    purchases: fmt(p, d => ({ title: d.title || '', price: d.price, granted: !!d.granted, expiresAt: tms(d.expiresAt) }))
  };
}

/* ---------- ভিডিও ---------- */
const purchaseOk = d => d && (!d.expiresAt || tms(d.expiresAt) > Date.now());
async function hVidAccess(env, req, b){
  const { uid } = await needUser(env, req), id = cleanId(b.id);
  const p = await getDoc(env, 'purchases/' + uid + '_' + id);
  if (!p.exists) return { purchased: false, expired: false };
  const ex = tms(p.data.expiresAt);
  return purchaseOk(p.data) ? { purchased: true, expiresAt: ex } : { purchased: false, expired: true };
}
async function hVidBuy(env, req, b){
  const { uid } = await needUser(env, req), id = cleanId(b.id), pid = uid + '_' + id;
  let expiresAt = 0;
  await runTx(env, async tx => {
    const v = await getDoc(env, 'videos/' + id, tx);
    if (!v.exists || v.data.hidden || !v.data.paid) throw new AppErr('ভিডিও পাওয়া যায়নি');
    const p = await getDoc(env, 'purchases/' + pid, tx);
    if (p.exists && purchaseOk(p.data)) { expiresAt = tms(p.data.expiresAt); return []; }
    const price = r2(effPrice(v.data)); if (!(price > 0)) throw new AppErr('ভিডিওর দাম ঠিক নেই');
    const u = await getDoc(env, 'users/' + uid, tx), bal = +(u.data || {}).balance || 0;
    if (bal < price) throw new AppErr('ব্যালেন্স কম — VIP লিংক জমা দিয়ে ব্যালেন্স যোগ করুন', 'low-balance');
    const days = +v.data.validDays || 0, exp = days > 0 ? new Date(Date.now() + days * 86400000) : null;
    expiresAt = exp ? exp.getTime() : 0;
    return [
      W.upd(env, 'users/' + uid, { balance: r2(bal - price) }),
      W.set(env, 'purchases/' + pid, { uid, vid: id, title: v.data.title || '', price, at: new Date(), validDays: days, expiresAt: exp }),
      W.set(env, 'transactions/' + crypto.randomUUID(), { uid, type: 'deduct', kind: 'video', amount: price, title: 'ভিডিও আনলক: ' + (v.data.title || ''), ref: id, at: new Date() })
    ];
  });
  return { expiresAt };
}
async function hVidPlay(env, req, b){
  const id = cleanId(b.id), v = await getDoc(env, 'videos/' + id);
  if (!v.exists || v.data.hidden) throw new AppErr('ভিডিও পাওয়া যায়নি', 'nf', 404);
  if (v.data.paid) {
    const { uid } = await needUser(env, req), p = await getDoc(env, 'purchases/' + uid + '_' + id);
    if (!p.exists) throw new AppErr('আগে ভিডিওটি আনলক করুন', 'locked', 403);
    if (!purchaseOk(p.data)) throw new AppErr('আপনার মেয়াদ শেষ হয়েছে', 'locked', 403);
  }
  await checkGate(env, await getSettings(env), b.pass, id);
  const s = await getDoc(env, 'videos/' + id + '/private/src'), d = s.data || {};
  let items = (d.items && d.items.length) ? d.items : (d.url ? [{ title: v.data.title, url: d.url }] : (v.data.url ? [{ title: v.data.title, url: v.data.url }] : []));
  items = items.filter(i => isHttp(i.url)).map(i => ({ title: i.title || '', url: i.url }));
  if (!items.length) throw new AppErr('ভিডিও লিংক পাওয়া যায়নি');
  return { items };
}

/* ---------- লাইভ চ্যাট ---------- */
async function hChatMsgs(env, req){
  const { uid } = await needUser(env, req);
  const rows = await query(env, 'msgs', [], { parent: 'chats/' + uid, order: 'at', desc: true, limit: 150 });
  const chat = await getDoc(env, 'chats/' + uid);
  if (chat.exists && chat.data.unreadUser) await commit(env, [W.upd(env, 'chats/' + uid, { unreadUser: false })]).catch(() => {});
  return { msgs: rows.map(r => ({ from: r.data.from === 'user' ? 'user' : 'admin', text: r.data.text || '', at: tms(r.data.at) })).reverse() };
}
async function hChatSend(env, req, b){
  const { uid, user } = await needUser(env, req), text = cleanStr(b.text, 500);
  if (!text) throw new AppErr('মেসেজ লিখুন');
  await commit(env, [
    W.merge(env, 'chats/' + uid, { name: user.name || '', email: user.username || '', last: text, lastAt: new Date(), unreadAdmin: true }),
    W.set(env, 'chats/' + uid + '/msgs/' + crypto.randomUUID(), { from: 'user', text, at: new Date() })
  ]);
  return {};
}

/* ---------- অ্যাডমিন: লিংক রিকোয়েস্ট ---------- */
async function hLinkApprove(env, req, b){
  const adm = await needAdmin(env, req), id = cleanId(b.id);
  await runTx(env, async tx => {
    const r = await getDoc(env, 'linkRequests/' + id, tx);
    if (!r.exists) throw new AppErr('রিকোয়েস্ট পাওয়া যায়নি');
    if (r.data.status !== 'pending') throw new AppErr('আগেই প্রসেস হয়েছে', 'done');
    const u = await getDoc(env, 'users/' + r.data.uid, tx);
    if (!u.exists) throw new AppErr('ইউজার পাওয়া যায়নি');
    const price = r2(r.data.price), bal = r2((+u.data.balance || 0) + price);
    return [
      W.upd(env, 'linkRequests/' + id, { status: 'approved', credited: true, by: adm.email, doneAt: new Date() }),
      W.upd(env, 'users/' + r.data.uid, { balance: bal }),
      W.set(env, 'transactions/' + crypto.randomUUID(), { uid: r.data.uid, type: 'add', kind: 'link', amount: price, title: 'লিংক Approved: ' + r.data.groupName, ref: id, at: new Date(), by: adm.email }),
      W.set(env, 'notifications/' + crypto.randomUUID(), { to: r.data.uid, title: '✅ লিংক Approved', body: r.data.groupName + ' — ' + money(price) + ' আপনার ব্যালেন্সে যোগ হয়েছে।', at: new Date() })
    ];
  });
  return {};
}
async function hLinkReject(env, req, b){
  const adm = await needAdmin(env, req), id = cleanId(b.id), reason = cleanStr(b.reason, 300);
  await runTx(env, async tx => {
    const r = await getDoc(env, 'linkRequests/' + id, tx);
    if (!r.exists) throw new AppErr('রিকোয়েস্ট পাওয়া যায়নি');
    if (r.data.status !== 'pending') throw new AppErr('আগেই প্রসেস হয়েছে', 'done');
    return [
      W.upd(env, 'linkRequests/' + id, { status: 'rejected', reason, by: adm.email, doneAt: new Date() }),
      W.set(env, 'notifications/' + crypto.randomUUID(), { to: r.data.uid, title: '❌ লিংক Reject', body: r.data.groupName + (reason ? ' — কারণ: ' + reason : ''), at: new Date() })
    ];
  });
  return {};
}

/* ---------- অ্যাডমিন: উইথড্র ---------- */
async function hWdProcess(env, req, b){
  const adm = await needAdmin(env, req), id = cleanId(b.id), action = String(b.action || '');
  const feeCfg = +env.WD_FEE || 10;
  if (action !== 'approve' && action !== 'reject') throw new AppErr('ভুল অনুরোধ');
  const trx = cleanStr(b.trxId, 80), reason = cleanStr(b.reason, 300);
  if (action === 'approve' && !trx) throw new AppErr('Transaction ID দিন');
  if (action === 'reject' && !reason) throw new AppErr('কারণ লিখুন');
  await runTx(env, async tx => {
    const w = await getDoc(env, 'withdrawals/' + id, tx);
    if (!w.exists) throw new AppErr('রিকোয়েস্ট পাওয়া যায়নি');
    if (w.data.status !== 'pending') throw new AppErr('আগেই প্রসেস হয়েছে', 'done');
    const amt = r2(w.data.amount), nid = crypto.randomUUID();
    if (action === 'approve') return [
      W.upd(env, 'withdrawals/' + id, { status: 'approved', trxId: trx, by: adm.email, doneAt: new Date() }),
      W.set(env, 'notifications/' + nid, { to: w.data.uid, title: '✅ উইথড্র সম্পন্ন', body: money(amt) + ' আপনার ' + w.data.method + ' নম্বরে পাঠানো হয়েছে। Transaction ID: ' + trx, at: new Date() })
    ];
    const fee = b.wrongInfo ? Math.min(feeCfg, amt) : 0, back = r2(amt - fee);
    const u = await getDoc(env, 'users/' + w.data.uid, tx);
    const ws = [
      W.upd(env, 'withdrawals/' + id, fee ? { status: 'rejected', reason, fee, by: adm.email, doneAt: new Date() } : { status: 'rejected', reason, by: adm.email, doneAt: new Date() }),
      W.set(env, 'notifications/' + nid, { to: w.data.uid, title: '❌ উইথড্র বাতিল', body: 'কারণ: ' + reason + (fee ? ' · ভুল তথ্যের কারণে ' + money(fee) + ' কাটা হয়েছে' : '') + (back > 0 ? ' · ' + money(back) + ' ব্যালেন্সে ফেরত দেওয়া হয়েছে।' : ''), at: new Date() })
    ];
    if (u.exists && back > 0) ws.push(W.upd(env, 'users/' + w.data.uid, { balance: r2((+u.data.balance || 0) + back) }));
    if (fee) ws.push(W.set(env, 'transactions/' + crypto.randomUUID(), { uid: w.data.uid, type: 'deduct', kind: 'fee', amount: fee, title: 'ভুল তথ্যের কারণে উইথড্র ক্যান্সেল ফি', ref: id, at: new Date(), by: adm.email }));
    return ws;
  });
  return {};
}

/* ---------- অ্যাডমিন: ইউজার ---------- */
async function hUserBalance(env, req, b){
  const adm = await needAdmin(env, req), uid = cleanId(b.uid), mode = b.mode === 'deduct' ? 'deduct' : 'add', amt = r2(b.amount), title = cleanStr(b.title, 120);
  if (!(amt > 0) || !title) throw new AppErr('টাকা ও Title দিন');
  await runTx(env, async tx => {
    const u = await getDoc(env, 'users/' + uid, tx); if (!u.exists) throw new AppErr('ইউজার পাওয়া যায়নি');
    const bal = +u.data.balance || 0;
    if (mode === 'deduct' && amt > bal) throw new AppErr('ব্যালেন্সের চেয়ে বেশি কাটা যাবে না');
    return [
      W.upd(env, 'users/' + uid, { balance: r2(mode === 'add' ? bal + amt : bal - amt) }),
      W.set(env, 'transactions/' + crypto.randomUUID(), { uid, type: mode, kind: 'admin', amount: amt, title, at: new Date(), by: adm.email })
    ];
  });
  return {};
}
async function hUserUpdate(env, req, b){
  await needAdmin(env, req);
  const uid = cleanId(b.uid), name = cleanStr(b.name, 60), un = String(b.username || '').trim().toLowerCase(), pw = String(b.password || ''), cf = String(b.confirm || '');
  if (name.length < 2) throw new AppErr('নাম লিখুন (কমপক্ষে ২ অক্ষর)');
  checkUn(un);
  if (pw || cf) { if (pw.length < 6) throw new AppErr('নতুন Password কমপক্ষে ৬ অক্ষরের হতে হবে'); if (pw !== cf) throw new AppErr('নতুন Password ও Confirm মিলছে না'); }
  const cred = pw ? await newCred(pw) : null;
  await runTx(env, async tx => {
    const u = await getDoc(env, 'users/' + uid, tx); if (!u.exists) throw new AppErr('ইউজার পাওয়া যায়নি');
    const ws = [], old = u.data.username;
    if (old !== un) {
      const nu = await getDoc(env, 'usernames/' + un, tx);
      if (nu.exists && nu.data.uid !== uid) throw new AppErr('এই Username আগেই নেওয়া হয়েছে', 'dupuser');
      ws.push(W.set(env, 'usernames/' + un, { uid }));
      if (old) ws.push(W.del(env, 'usernames/' + old));
    }
    ws.push(W.upd(env, 'users/' + uid, { name, username: un }));
    if (cred) ws.push(W.set(env, 'credentials/' + uid, cred));
    return ws;
  });
  return {};
}
async function hUsersDelete(env, req, b){
  await needAdmin(env, req);
  const uids = (Array.isArray(b.uids) ? b.uids : []).map(cleanId).filter(Boolean).slice(0, 50);
  for (const uid of uids) {
    const del = [], u = await getDoc(env, 'users/' + uid);
    const jobs = [
      ['linkRequests', 'uid'], ['withdrawals', 'uid'], ['transactions', 'uid'], ['purchases', 'uid'], ['notifications', 'to'], ['dailyCounts', 'uid']
    ].map(([c, f]) => query(env, c, [[f, 'EQUAL', uid]]).then(rows => rows.forEach(r => del.push(W.del(env, r.path)))));
    jobs.push(query(env, 'msgs', [], { parent: 'chats/' + uid }).then(rows => rows.forEach(r => del.push(W.del(env, r.path)))));
    await Promise.all(jobs);
    del.push(W.del(env, 'chats/' + uid), W.del(env, 'credentials/' + uid), W.del(env, 'users/' + uid));
    if (u.exists && u.data.username) del.push(W.del(env, 'usernames/' + u.data.username));
    await commit(env, del);
  }
  return {};
}

/* ---------- Telegram ---------- */
async function tg(token, method, params){
  try {
    const r = await fetch('https://api.telegram.org/bot' + token + '/' + method, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params || {}) });
    return await r.json();
  } catch (e) { return { ok: false, description: 'Telegram-এ পৌঁছানো যায়নি' }; }
}
const chatTitle = c => c.title || [c.first_name, c.last_name].filter(Boolean).join(' ') || (c.username ? '@' + c.username : String(c.id));
function applyUpdates(chats, updates){
  const map = {}; (chats || []).forEach(c => { map[String(c.id)] = c; });
  (updates || []).forEach(u => {
    const m = u.my_chat_member, c = m ? m.chat : (u.message || u.edited_message || u.channel_post || u.edited_channel_post || {}).chat;
    if (!c || c.id === undefined) return;
    const k = String(c.id), st = m && m.new_chat_member && m.new_chat_member.status;
    if (st === 'left' || st === 'kicked') { delete map[k]; return; }
    map[k] = { id: c.id, title: chatTitle(c), type: c.type || '' };
  });
  return Object.keys(map).map(k => map[k]);
}
const botSummary = d => ({ id: d.id, name: d.data.name, enabled: !!d.data.enabled, status: d.data.status || 'new', statusText: d.data.statusText || '', username: d.data.username || '', tokenHint: d.data.tokenHint || '', chats: (d.data.chats || []).map(c => ({ title: c.title, type: c.type })) });
const TOKEN_RE = /^\d{5,}:[A-Za-z0-9_-]{30,}$/;
async function connectBot(env, id, origin){
  const bd = await getDoc(env, 'botConfigs/' + id); if (!bd.exists) throw new AppErr('Bot পাওয়া যায়নি');
  const token = await decTok(env, bd.data.tokenEnc), me = await tg(token, 'getMe');
  if (!me.ok) { await commit(env, [W.upd(env, 'botConfigs/' + id, { status: 'error', statusText: 'Token সঠিক নয় বা Bot পাওয়া যায়নি', updatedAt: new Date() })]); return; }
  let chats = bd.data.chats || [];
  await tg(token, 'deleteWebhook', { drop_pending_updates: false });
  const up = await tg(token, 'getUpdates', { limit: 100, timeout: 0, allowed_updates: ['message', 'channel_post', 'my_chat_member'] });
  if (up.ok) chats = applyUpdates(chats, up.result);
  const wh = await tg(token, 'setWebhook', { url: origin + '/tg/' + id, secret_token: bd.data.webhookSecret, allowed_updates: ['message', 'channel_post', 'my_chat_member'], drop_pending_updates: false, max_connections: 10 });
  const text = !wh.ok ? 'Webhook সেট করা যায়নি: ' + (wh.description || '') : (chats.length ? 'সংযুক্ত — ' + bn(chats.length) + 'টি চ্যাট/চ্যানেল শনাক্ত হয়েছে' : 'সংযুক্ত — এখনো কোনো চ্যাট/চ্যানেল শনাক্ত হয়নি। Bot-কে চ্যানেল/গ্রুপে Admin করুন (বা Bot-কে /start দিন), তারপর রিফ্রেশ চাপুন');
  await commit(env, [W.upd(env, 'botConfigs/' + id, { status: wh.ok ? 'connected' : 'error', statusText: text, username: me.result.username || '', chats, updatedAt: new Date() })]);
}
async function hBotsList(env, req){
  await needAdmin(env, req);
  const rows = await query(env, 'botConfigs', []);
  return { bots: rows.sort((a, b) => tms(a.data.createdAt) - tms(b.data.createdAt)).map(botSummary) };
}
async function hBotSave(env, req, b, url){
  await needAdmin(env, req);
  const name = cleanStr(b.name, 60), token = String(b.token || '').trim(), id = b.id ? cleanId(b.id) : '';
  if (!name) throw new AppErr('Bot Name দিন');
  if (id) {
    const d = await getDoc(env, 'botConfigs/' + id); if (!d.exists) throw new AppErr('Bot পাওয়া যায়নি');
    const data = { name, enabled: b.enabled !== false, updatedAt: new Date() };
    if (token) {
      if (!TOKEN_RE.test(token)) throw new AppErr('Bot API Token সঠিক নয়');
      data.tokenEnc = await encTok(env, token); data.tokenHint = token.split(':')[0] + ':••••' + token.slice(-4); data.status = 'new'; data.statusText = ''; data.chats = [];
      const old = await decTok(env, d.data.tokenEnc).catch(() => ''); if (old) await tg(old, 'deleteWebhook', {});
    }
    await commit(env, [W.upd(env, 'botConfigs/' + id, data)]);
    if (token) await connectBot(env, id, url.origin);
    return {};
  }
  if (!TOKEN_RE.test(token)) throw new AppErr('Bot API Token সঠিক নয় (BotFather-এর দেওয়া পুরো Token দিন)');
  const nid = rndHex(8);
  await commit(env, [W.set(env, 'botConfigs/' + nid, { name, tokenEnc: await encTok(env, token), tokenHint: token.split(':')[0] + ':••••' + token.slice(-4), enabled: b.enabled !== false, status: 'new', statusText: '', username: '', webhookSecret: rndHex(16), chats: [], createdAt: new Date(), updatedAt: new Date() })]);
  await connectBot(env, nid, url.origin);
  return { id: nid };
}
async function hBotToggle(env, req, b){ await needAdmin(env, req); await commit(env, [W.upd(env, 'botConfigs/' + cleanId(b.id), { enabled: !!b.enabled, updatedAt: new Date() })]); return {}; }
async function hBotDelete(env, req, b){
  await needAdmin(env, req); const id = cleanId(b.id), d = await getDoc(env, 'botConfigs/' + id);
  if (d.exists) { const t = await decTok(env, d.data.tokenEnc).catch(() => ''); if (t) await tg(t, 'deleteWebhook', {}); await commit(env, [W.del(env, 'botConfigs/' + id)]); }
  return {};
}
async function hBotRefresh(env, req, b){
  await needAdmin(env, req); const id = cleanId(b.id), d = await getDoc(env, 'botConfigs/' + id);
  if (!d.exists) throw new AppErr('Bot পাওয়া যায়নি');
  const token = await decTok(env, d.data.tokenEnc), me = await tg(token, 'getMe');
  if (!me.ok) { await commit(env, [W.upd(env, 'botConfigs/' + id, { status: 'error', statusText: 'Token সঠিক নয় বা Bot পাওয়া যায়নি', updatedAt: new Date() })]); return {}; }
  const keep = [];
  for (const c of (d.data.chats || [])) { const r = await tg(token, 'getChat', { chat_id: c.id }); if (r.ok) keep.push({ id: c.id, title: chatTitle(r.result), type: r.result.type || c.type }); }
  const wi = await tg(token, 'getWebhookInfo', {}), url = (wi.result && wi.result.url) || '';
  const text = keep.length ? 'সংযুক্ত — ' + bn(keep.length) + 'টি চ্যাট/চ্যানেল' : 'সংযুক্ত — এখনো কোনো চ্যাট/চ্যানেল শনাক্ত হয়নি। Bot-কে চ্যানেল/গ্রুপে Admin করুন (বা Bot-কে /start দিন), তারপর রিফ্রেশ চাপুন';
  await commit(env, [W.upd(env, 'botConfigs/' + id, { status: url ? 'connected' : 'error', statusText: url ? text : 'Webhook বন্ধ — Token আবার Save করুন', username: me.result.username || '', chats: keep, updatedAt: new Date() })]);
  return {};
}
async function tgWebhook(env, req, url, id){
  if (req.method !== 'POST') return new Response('ok');
  id = cleanId(id);
  const d = await getDoc(env, 'botConfigs/' + id);
  if (!d.exists || !safeEq(req.headers.get('X-Telegram-Bot-Api-Secret-Token') || '', d.data.webhookSecret || '')) return new Response('forbidden', { status: 403 });
  let u; try { u = await req.json(); } catch (e) { return new Response('ok'); }
  const before = JSON.stringify(d.data.chats || []), chats = applyUpdates(d.data.chats || [], [u]);
  if (JSON.stringify(chats) !== before) await commit(env, [W.upd(env, 'botConfigs/' + id, { chats, status: 'connected', statusText: 'সংযুক্ত — ' + bn(chats.length) + 'টি চ্যাট/চ্যানেল শনাক্ত হয়েছে', updatedAt: new Date() })]);
  return new Response('ok');
}
async function sendToBots(env, text, btnText, btnUrl){
  const bots = (await query(env, 'botConfigs', [])).filter(d => d.data.enabled);
  const details = await Promise.all(bots.map(async d => {
    const r = { bot: d.data.name, sent: 0, failed: 0, error: '' };
    try {
      const token = await decTok(env, d.data.tokenEnc), chats = d.data.chats || [];
      if (!chats.length) { r.error = 'কোনো চ্যাট/চ্যানেল শনাক্ত হয়নি'; return r; }
      const rm = (btnText && isHttp(btnUrl)) ? { inline_keyboard: [[{ text: btnText, url: btnUrl }]] } : undefined;
      const res = await Promise.all(chats.map(c => tg(token, 'sendMessage', { chat_id: c.id, text, disable_web_page_preview: true, reply_markup: rm })));
      res.forEach(x => { if (x.ok) r.sent++; else { r.failed++; r.error = r.error || String(x.description || 'ব্যর্থ').slice(0, 120); } });
    } catch (e) { r.error = 'Bot Token পড়া যায়নি'; r.failed++; }
    return r;
  }));
  const ok = details.filter(x => x.sent > 0).length;
  return { total: bots.length, ok, failed: bots.length - ok, details };
}
async function buildNotice(env, b){
  const type = String(b.type || ''), site = siteUrl(env);
  if (type === 'link') {
    const d = await getDoc(env, 'freeLinks/' + cleanId(b.refId)); if (!d.exists) throw new AppErr('লিংক পাওয়া যায়নি');
    return { type, label: 'Link Notification', title: d.data.title, text: '🔔 নতুন একটি লিংক অ্যাড হয়েছে\n\nটাইটেল: ' + d.data.title, btnText: '🌐 এখনই দেখুন', btnUrl: site, key: 'link_' + d.id };
  }
  if (type === 'free_video' || type === 'paid_video') {
    const d = await getDoc(env, 'videos/' + cleanId(b.refId)); if (!d.exists) throw new AppErr('ভিডিও পাওয়া যায়নি');
    if (type === 'paid_video' && !d.data.paid) throw new AppErr('এটি পেইড ভিডিও নয়');
    if (type === 'free_video' && d.data.paid) throw new AppErr('এটি ফ্রি ভিডিও নয়');
    const text = type === 'paid_video'
      ? '🎬 নতুন একটি পেইড ভিডিও অ্যাড করা হয়েছে\n\nটাইটেল: ' + d.data.title + '\n\nদাম: ' + money(effPrice(d.data))
      : '🎬 নতুন একটি ফ্রি ভিডিও অ্যাড করা হয়েছে\n\nটাইটেল: ' + d.data.title;
    return { type, label: type === 'paid_video' ? 'Paid Video Notification' : 'Free Video Notification', title: d.data.title, text, btnText: '▶️ এখনই দেখুন', btnUrl: site, key: type + '_' + d.id };
  }
  if (type === 'custom') {
    const title = String(b.title || '').trim().slice(0, 300), msg = String(b.message || '').trim(), nonce = cleanId(b.nonce);
    if (!title) throw new AppErr('টাইটেল দিন'); if (!msg) throw new AppErr('মেসেজ লিখুন'); if (nonce.length < 6) throw new AppErr('ভুল অনুরোধ');
    const text = title + '\n\n' + msg; if (text.length > 4000) throw new AppErr('মেসেজ অনেক বড় (সর্বোচ্চ ৪০০০ অক্ষর)');
    const bt = String(b.btnText || '').trim().slice(0, 60) || '▶️ এখনই দেখুন', bu = String(b.btnUrl || '').trim() || site;
    if (!isHttp(bu)) throw new AppErr('Button Link ঠিক নয় (https:// দিয়ে শুরু হতে হবে)');
    return { type, label: 'Custom Notification', title, text, btnText: bt, btnUrl: bu, key: 'custom_' + nonce };
  }
  throw new AppErr('ভুল নোটিফিকেশন টাইপ');
}
async function hNotify(env, req, b){
  const adm = await needAdmin(env, req), n = await buildNotice(env, b), hid = n.key;
  try {
    await commit(env, [W.set(env, 'notificationHistory/' + hid, { type: n.type, typeLabel: n.label, title: n.title, message: n.text, at: new Date(), status: 'sending', totalBots: 0, successful: 0, failed: 0, details: [], by: adm.email }, { exists: false })]);
  } catch (e) {
    if (e.fsStatus === 'ALREADY_EXISTS' || e.fsStatus === 'FAILED_PRECONDITION') throw new AppErr('এই নোটিফিকেশন আগেই পাঠানো হয়েছে (Duplicate প্রতিরোধ)', 'dup');
    throw e;
  }
  const r = await sendToBots(env, n.text, n.btnText, n.btnUrl);
  const status = r.total === 0 ? 'no_bot' : (r.ok === r.total ? 'success' : (r.ok > 0 ? 'partial' : 'failed'));
  await commit(env, [W.upd(env, 'notificationHistory/' + hid, { status, totalBots: r.total, successful: r.ok, failed: r.failed, details: r.details })]).catch(() => {});
  return { totalBots: r.total, okBots: r.ok, failedBots: r.failed, status };
}

/* ---------- রাউটার ---------- */
const ROUTES = {
  'GET /health': async () => ({ time: Date.now() }),
  'POST /auth/register': hRegister, 'POST /auth/login': hLogin, 'GET /me': hMe,
  'POST /gate/start': hGateStart, 'POST /gate/finish': hGateFinish,
  'POST /links/submit': hSubmit,
  'POST /wd/request': hWdRequest, 'GET /history': hHistory,
  'POST /video/access': hVidAccess, 'POST /video/buy': hVidBuy, 'POST /video/play': hVidPlay,
  'GET /chat/msgs': hChatMsgs, 'POST /chat/send': hChatSend,
  'POST /admin/link/approve': hLinkApprove, 'POST /admin/link/reject': hLinkReject,
  'POST /admin/wd/process': hWdProcess,
  'POST /admin/user/balance': hUserBalance, 'POST /admin/user/update': hUserUpdate, 'POST /admin/users/delete': hUsersDelete,
  'POST /admin/bots/list': hBotsList, 'POST /admin/bots/save': hBotSave, 'POST /admin/bots/toggle': hBotToggle,
  'POST /admin/bots/delete': hBotDelete, 'POST /admin/bots/refresh': hBotRefresh,
  'POST /admin/notify': hNotify
};
export default {
  async fetch(req, env){
    const url = new URL(req.url), path = url.pathname.replace(/\/+$/, '') || '/', ch = corsHeaders(env, req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: ch });
    try {
      if (path.indexOf('/tg/') === 0) return await tgWebhook(env, req, url, path.slice(4));
      const o = req.headers.get('Origin'), al = allowList(env);
      if (o && !al.includes('*') && !al.includes(o)) throw new AppErr('এই ডোমেইন থেকে অনুমতি নেই', 'cors', 403);
      let body = {};
      if (req.method === 'POST') {
        const t = await req.text();
        if (t.length > 100000) throw new AppErr('অনুরোধ অনেক বড়', 'big', 413);
        try { body = t ? JSON.parse(t) : {}; } catch (e) { throw new AppErr('ভুল অনুরোধ'); }
        if (!body || typeof body !== 'object') body = {};
      }
      const h = ROUTES[req.method + ' ' + path];
      if (!h) throw new AppErr('পাওয়া যায়নি', 'nf', 404);
      return json(Object.assign({ ok: true }, await h(env, req, body, url)), 200, ch);
    } catch (e) {
      if (e instanceof AppErr) return json(Object.assign({ ok: false, error: e.message, code: e.code }, e.extra || {}), e.status, ch);
      console.error(e && e.stack || e);
      return json({ ok: false, error: 'সার্ভারে সমস্যা হয়েছে, আবার চেষ্টা করুন', code: 'server' }, 500, ch);
    }
  }
};
