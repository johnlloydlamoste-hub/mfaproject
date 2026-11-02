'use strict';
// Zero-dependency web app: password + TOTP (RFC 6238) multi-factor login,
// then a private image "folder" with a log-out button.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(DATA, 'uploads');
const DB_FILE = path.join(DATA, 'users.json');
const PUBLIC = path.join(__dirname, 'public');
const MAX_IMAGE = 8 * 1024 * 1024; // 8 MB
const ISSUER = 'ImageFolder';

fs.mkdirSync(UPLOADS, { recursive: true });
let db = { users: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { /* first run */ }
const save = () => {
  fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(DB_FILE + '.tmp', DB_FILE);
};

/* ---------- TOTP ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) {
  let bits = 0, v = 0, out = '';
  for (const b of buf) {
    v = ((v << 8) | b) & 0xffff; bits += 8;
    while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31];
  return out;
}
function b32dec(s) {
  let bits = 0, v = 0; const out = [];
  for (const c of s) {
    v = ((v << 5) | B32.indexOf(c)) & 0xffff; bits += 5;
    if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(key, counter) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const o = h[19] & 15;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6;
  return String(n).padStart(6, '0');
}
function verifyTotp(user, code) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  const step = Math.floor(Date.now() / 30000);
  const key = b32dec(user.secret);
  for (let i = -1; i <= 1; i++) { // tolerate ±30s clock drift
    const s = step + i;
    const expected = Buffer.from(hotp(key, s));
    if (crypto.timingSafeEqual(expected, Buffer.from(code)) && s > (user.lastStep || 0)) {
      user.lastStep = s; save(); // block replay of an already-used code
      return true;
    }
  }
  return false;
}
const otpauthUri = (u) =>
  `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(u.username)}` +
  `?secret=${u.secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`;

/* ---------- passwords ---------- */
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  const [s, h] = stored.split(':');
  const got = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64);
  return crypto.timingSafeEqual(got, Buffer.from(h, 'hex'));
}
const DUMMY = hashPw('dummy-password'); // equalises timing for unknown usernames

/* ---------- sessions & throttling ---------- */
// stage: 'mfa' (password ok, needs code) | 'setup' (needs to enrol authenticator) | 'full'
const sessions = new Map();
const TTL = { mfa: 10 * 60e3, setup: 10 * 60e3, full: 2 * 3600e3 };
function newSession(userId, stage) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { userId, stage, created: Date.now(), tries: 0 });
  return sid;
}
function getSession(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || '');
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s) return null;
  if (Date.now() - s.created > TTL[s.stage]) { sessions.delete(m[1]); return null; }
  s.sid = m[1];
  return s;
}
function cookie(sid, maxAge) {
  return `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` +
    (process.env.COOKIE_SECURE ? '; Secure' : '');
}
const fails = new Map(); // "ip|user" -> {n, until}
function locked(key) { const f = fails.get(key); return f && f.until > Date.now(); }
function fail(key) {
  const f = fails.get(key) || { n: 0, until: 0 };
  if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; }
  if (++f.n >= 5) f.until = Date.now() + 5 * 60e3;
  fails.set(key, f);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.created > TTL[s.stage]) sessions.delete(k);
  for (const [k, f] of fails) if (f.until && f.until < now) fails.delete(k);
}, 60e3).unref();

/* ---------- helpers ---------- */
const SEC_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; " +
    "style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};
function send(res, code, body, type = 'application/json', extra = {}) {
  res.writeHead(code, { ...SEC_HEADERS, 'Content-Type': type, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const json = (res, code, obj, extra) => send(res, code, obj, 'application/json', extra);

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  try { return JSON.parse((await readBody(req, 10 * 1024)).toString() || '{}'); }
  catch (e) { if (e.status) throw e; return {}; }
}

const IMG_TYPES = {
  png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
};
function sniff(b) { // identify by magic bytes, never trust the client's claim
  if (b.length > 12) {
    if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
    if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
    if (b.subarray(0, 4).toString() === 'GIF8') return 'gif';
    if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return 'webp';
  }
  return null;
}
const STATIC = {
  '/style.css': ['style.css', 'text/css'],
  '/login.js': ['login.js', 'application/javascript'],
  '/app.js': ['app.js', 'application/javascript'],
};
const page = (f) => fs.readFileSync(path.join(PUBLIC, f));

/* ---------- routes ---------- */
async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const ip = req.socket.remoteAddress;
  const sess = getSession(req);

  if (req.method === 'GET') {
    if (p === '/') return send(res, 200, page(sess && sess.stage === 'full' ? 'app.html' : 'index.html'), 'text/html; charset=utf-8');
    if (STATIC[p]) return send(res, 200, page(STATIC[p][0]), STATIC[p][1]);
  }

  if (!p.startsWith('/api/')) return json(res, 404, { error: 'Not found' });
  // CSRF defence in depth (cookie is also SameSite=Strict)
  if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'fetch')
    return json(res, 403, { error: 'Bad request' });

  const full = sess && sess.stage === 'full' ? db.users[sess.userId] : null;

  /* --- auth --- */
  if (p === '/api/register' && req.method === 'POST') {
    const { username, password } = await readJson(req);
    const name = String(username || '').trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,32}$/.test(name)) return json(res, 400, { error: 'Username must be 3–32 letters, numbers, . _ -' });
    if (typeof password !== 'string' || password.length < 8 || password.length > 200) return json(res, 400, { error: 'Password must be at least 8 characters' });
    if (Object.values(db.users).some((u) => u.username === name)) return json(res, 409, { error: 'That username is taken' });
    const id = crypto.randomBytes(16).toString('hex');
    const user = { id, username: name, pw: hashPw(password), secret: b32enc(crypto.randomBytes(20)), mfa: false, lastStep: 0, images: [] };
    db.users[id] = user; save();
    const sid = newSession(id, 'setup');
    return json(res, 200, { setup: true, secret: user.secret, uri: otpauthUri(user) }, { 'Set-Cookie': cookie(sid, 600) });
  }

  if (p === '/api/login' && req.method === 'POST') {
    const { username, password } = await readJson(req);
    const name = String(username || '').trim().toLowerCase();
    const key = ip + '|' + name;
    if (locked(key)) return json(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const user = Object.values(db.users).find((u) => u.username === name);
    const ok = checkPw(String(password || ''), user ? user.pw : DUMMY) && !!user;
    if (!ok) { fail(key); return json(res, 401, { error: 'Invalid username or password' }); }
    fails.delete(key);
    if (!user.mfa) { // registered but never finished authenticator enrolment
      const sid = newSession(user.id, 'setup');
      return json(res, 200, { setup: true, secret: user.secret, uri: otpauthUri(user) }, { 'Set-Cookie': cookie(sid, 600) });
    }
    return json(res, 200, { mfa: true }, { 'Set-Cookie': cookie(newSession(user.id, 'mfa'), 600) });
  }

  if (p === '/api/mfa' && req.method === 'POST') { // second factor (login) or enrolment confirmation
    if (!sess || (sess.stage !== 'mfa' && sess.stage !== 'setup')) return json(res, 401, { error: 'Session expired. Sign in again.' });
    const { code } = await readJson(req);
    const user = db.users[sess.userId];
    if (!verifyTotp(user, String(code || '').replace(/\s/g, ''))) {
      if (++sess.tries >= 5) { sessions.delete(sess.sid); return json(res, 429, { error: 'Too many wrong codes. Sign in again.', restart: true }, { 'Set-Cookie': cookie('', 0) }); }
      return json(res, 401, { error: 'Incorrect code' });
    }
    if (sess.stage === 'setup') { user.mfa = true; save(); }
    sessions.delete(sess.sid); // fresh id after privilege change
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookie(newSession(user.id, 'full'), 7200) });
  }

  if (p === '/api/logout' && req.method === 'POST') {
    if (sess) sessions.delete(sess.sid);
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
  }

  /* --- images (fully authenticated) --- */
  if (!full) return json(res, 401, { error: 'Not signed in' });

  if (p === '/api/images' && req.method === 'GET')
    return json(res, 200, { images: full.images.map(({ id, name, size }) => ({ id, name, size })) });

  if (p === '/api/images' && req.method === 'POST') {
    const body = await readBody(req, MAX_IMAGE);
    const ext = sniff(body);
    if (!ext) return json(res, 415, { error: 'Only PNG, JPG, GIF or WebP images are allowed' });
    let name = 'image';
    try { name = decodeURIComponent(req.headers['x-filename'] || 'image'); } catch { /* keep default */ }
    name = path.basename(name).replace(/[^\w .()-]/g, '_').slice(0, 100) || 'image';
    const id = crypto.randomBytes(16).toString('hex');
    const dir = path.join(UPLOADS, full.id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, id + '.' + ext), body);
    full.images.push({ id, name, ext, size: body.length }); save();
    return json(res, 201, { id, name, size: body.length });
  }

  const m = /^\/api\/images\/([a-f0-9]{32})$/.exec(p);
  if (m) {
    const img = full.images.find((i) => i.id === m[1]);
    if (!img) return json(res, 404, { error: 'Not found' });
    const file = path.join(UPLOADS, full.id, img.id + '.' + img.ext);
    if (req.method === 'GET') return send(res, 200, fs.readFileSync(file), IMG_TYPES[img.ext], { 'Cache-Control': 'private, max-age=300' });
    if (req.method === 'DELETE') {
      try { fs.unlinkSync(file); } catch { /* already gone */ }
      full.images = full.images.filter((i) => i.id !== img.id); save();
      return json(res, 200, { ok: true });
    }
  }
  return json(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    if (!res.headersSent) json(res, e.status || 500, { error: e.status === 413 ? 'File too large (max 8 MB)' : 'Server error' });
    if (!e.status) console.error(e);
  });
});
if (require.main === module) server.listen(PORT, () => console.log(`Image Folder running at http://localhost:${PORT}`));

module.exports = { hotp, b32enc, b32dec };
