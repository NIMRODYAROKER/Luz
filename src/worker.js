// Luz — לו"ז יומי שלא עוזב אותך
// Cloudflare Worker + SQLite Durable Object. קבצי האתר ב-/public, כל /api/* מטופל כאן.
// כל 10 דקות רץ תזמון ששולח התראות למי שעוד לא סיים את המשימות.

import { DurableObject } from 'cloudflare:workers';

const TZ = 'Asia/Jerusalem';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol === 'http:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
      url.protocol = 'https:';
      return Response.redirect(url.toString(), 301);
    }
    if (url.pathname.startsWith('/api/')) {
      return withSecurityHeaders(await db(env).fetch(request));
    }
    const res = await env.ASSETS.fetch(request);
    const out = withSecurityHeaders(res);
    const type = res.headers.get('content-type') || '';
    if (type.includes('text/html') || url.pathname.endsWith('sw.js')) {
      out.headers.set('cache-control', 'no-cache, no-store, must-revalidate');
    }
    return out;
  },
  // תזמון: לא נגיש מבחוץ, רק Cloudflare מפעיל אותו
  async scheduled(event, env, ctx) {
    ctx.waitUntil(db(env).fetch('https://internal/internal/cron', { method: 'POST' }));
  }
};
const db = (env) => env.DB.get(env.DB.idFromName('main'));

function withSecurityHeaders(res) {
  const out = new Response(res.body, res);
  out.headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  out.headers.set('x-content-type-options', 'nosniff');
  out.headers.set('x-frame-options', 'DENY');
  out.headers.set('referrer-policy', 'strict-origin-when-cross-origin');
  out.headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  return out;
}

// ---------- עזרים ----------
const SESSION_DAYS = 90, MIN_PASS = 6, MAX_TASKS = 40;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg) => { throw new HttpError(400, msg); };
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});
const text = (t) => new Response(t, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
const norm = (s, max = 60) => String(s ?? '').trim().replace(/\s+/g, ' ').slice(0, max);
const intIn = (v, min, max, def) => { const n = Number(v); return Number.isInteger(n) && n >= min && n <= max ? n : def; };

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
function randomId(bytes = 12) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return b64u(a); }
const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function hashPassword(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256));
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
class Limiter {
  constructor() { this.hits = new Map(); }
  list(key, ms) { const now = Date.now(), a = (this.hits.get(key) || []).filter(t => t > now - ms); this.hits.set(key, a); return a; }
  over(key, max, ms) { return this.list(key, ms).length >= max; }
  add(key, ms) { this.list(key, ms).push(Date.now()); if (this.hits.size > 5000) this.hits.clear(); }
  clear(key) { this.hits.delete(key); }
}

// זמן מקומי בישראל
function local(t = Date.now()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    .formatToParts(new Date(t)).map(x => [x.type, x.value]));
  const day = `${p.year}-${p.month}-${p.day}`;
  const hour = Number(p.hour) % 24;
  return { day, dow: new Date(day + 'T12:00:00Z').getUTCDay(), hour, min: hour * 60 + Number(p.minute) };
}
const addDays = (day, n) => { const d = new Date(day + 'T12:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };
const dowOf = (day) => new Date(day + 'T12:00:00Z').getUTCDay();

// ---------- Web Push (VAPID + הצפנת aes128gcm) ----------
const enc = new TextEncoder();
const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };
async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8));
}
async function encryptPayload(sub, payload) {
  const uaPub = unb64u(sub.p256dh), authSecret = unb64u(sub.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(enc.encode(payload), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}

export class LuzDB extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.limiter = new Limiter();
    this.migrate();
  }
  q(query, ...b) { return this.sql.exec(query, ...b).toArray(); }
  one(query, ...b) { return this.q(query, ...b)[0] || null; }

  migrate() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pass_hash TEXT NOT NULL, salt TEXT NOT NULL, gate_key TEXT NOT NULL UNIQUE,
        remind_from INTEGER NOT NULL DEFAULT 9, remind_every INTEGER NOT NULL DEFAULT 30,
        quiet_from INTEGER NOT NULL DEFAULT 23, block_from INTEGER NOT NULL DEFAULT 8,
        last_push INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, created_day TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL, kind TEXT NOT NULL,
        days TEXT NOT NULL, by_hour INTEGER, sort INTEGER NOT NULL DEFAULT 0,
        from_day TEXT NOT NULL, to_day TEXT, created INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS checks (task_id TEXT NOT NULL, user_id INTEGER NOT NULL, day TEXT NOT NULL, status TEXT NOT NULL, t INTEGER NOT NULL, PRIMARY KEY (task_id, day));
      CREATE TABLE IF NOT EXISTS subs (endpoint TEXT PRIMARY KEY, user_id INTEGER NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS security_log (t INTEGER NOT NULL, kind TEXT NOT NULL, who TEXT, ip TEXT);
      CREATE INDEX IF NOT EXISTS tasks_user ON tasks(user_id);
      CREATE INDEX IF NOT EXISTS checks_user ON checks(user_id, day);
      CREATE INDEX IF NOT EXISTS subs_user ON subs(user_id);
    `);
    // עמודות חדשות: שעה עם דקות, X פעמים בשבוע. ממלאים מהנתונים הקיימים בלי למחוק כלום
    const addCol = (tbl, def, fill) => { try { this.sql.exec(`ALTER TABLE ${tbl} ADD COLUMN ${def}`); if (fill) this.sql.exec(fill); } catch {} };
    addCol('tasks', 'by_min INTEGER', 'UPDATE tasks SET by_min = by_hour * 60 WHERE by_hour IS NOT NULL');
    addCol('tasks', 'per_week INTEGER');
    addCol('users', 'remind_min INTEGER NOT NULL DEFAULT 540', 'UPDATE users SET remind_min = remind_from * 60');
    addCol('users', 'quiet_min INTEGER NOT NULL DEFAULT 1380', 'UPDATE users SET quiet_min = quiet_from * 60');
    this.sql.exec('DELETE FROM sessions WHERE created < ?', Date.now() - SESSION_DAYS * 864e5);
  }
  secLog(kind, who, ip) {
    this.sql.exec('INSERT INTO security_log (t, kind, who, ip) VALUES (?, ?, ?, ?)', Date.now(), kind, who || '', ip || '');
    this.sql.exec('DELETE FROM security_log WHERE t < ?', Date.now() - 30 * 864e5);
    console.warn('[security]', kind, who || '', ip || '');
  }

  async fetch(request) {
    try { return await this.handle(request); }
    catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: 'משהו נכשל בשרת. נסה שוב' }, 500);
    }
  }

  auth(request) {
    const h = request.headers.get('authorization') || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    const u = token && this.one('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.created > ?', token, Date.now() - SESSION_DAYS * 864e5);
    if (!u) throw new HttpError(401, 'צריך להתחבר');
    return u;
  }
  newSession(uid) { const t = randomId(24); this.sql.exec('INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)', t, uid, Date.now()); return t; }

  // ---------- לוגיקה של יום ----------
  // משימה של X פעמים בשבוע מופיעה כל יום עד שהשלמת את המכסה (השבוע מתחיל בראשון).
  // היא "חובה היום" רק כשנשארו בדיוק כמה ימים כמו הפעמים שחסרות.
  tasksOn(uid, day) {
    const dow = dowOf(day), ws = addDays(day, -dow);
    return this.q('SELECT * FROM tasks WHERE user_id = ? AND from_day <= ? AND (to_day IS NULL OR to_day > ?) ORDER BY sort, created', uid, day, day)
      .filter(t => {
        if (!t.per_week) return t.days.includes(String(dow));
        t.before = this.one("SELECT COUNT(*) AS c FROM checks WHERE task_id = ? AND status = 'done' AND day >= ? AND day < ?", t.id, ws, day).c;
        if (t.before >= t.per_week) return false;
        t.must = t.per_week - t.before >= 7 - dow;
        return true;
      });
  }
  checksOn(uid, day) {
    const m = {}; for (const c of this.q('SELECT task_id, status FROM checks WHERE user_id = ? AND day = ?', uid, day)) m[c.task_id] = c.status; return m;
  }
  dayResult(uid, day) {
    const tasks = this.tasksOn(uid, day), checks = this.checksOn(uid, day);
    const open = tasks.filter(t => t.kind === 'do' && checks[t.id] !== 'done' && (!t.per_week || t.must));
    const broke = tasks.filter(t => t.kind === 'dont' && checks[t.id] === 'broke');
    return { tasks, checks, open, broke, ok: !open.length && !broke.length, empty: !tasks.length };
  }
  streak(u) {
    const today = local().day;
    let s = 0, best = Number(this.kvGet('best:' + u.id) || 0);
    const todayRes = this.dayResult(u.id, today);
    let d = addDays(today, -1);
    for (let i = 0; i < 400 && d >= u.created_day; i++, d = addDays(d, -1)) {
      const r = this.dayResult(u.id, d);
      if (r.empty) continue;
      if (!r.ok) break;
      s++;
    }
    if (todayRes.ok && !todayRes.empty) s++;
    if (s > best) { best = s; this.kvSet('best:' + u.id, String(best)); }
    return { streak: s, best };
  }
  locked(u, l = local()) {
    const r = this.dayResult(u.id, l.day);
    // חסום רק כשעבר המועד של משימה שלא סומנה. משימה בלי שעה לא חוסמת
    return r.open.some(t => t.by_min != null && l.min >= t.by_min);
  }
  kvGet(k) { return this.one('SELECT v FROM kv WHERE k = ?', k)?.v ?? null; }
  kvSet(k, v) { this.sql.exec('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, v); }

  state(u) {
    const l = local(), r = this.dayResult(u.id, l.day);
    const all = this.q('SELECT * FROM tasks WHERE user_id = ? AND to_day IS NULL ORDER BY sort, created', u.id);
    // שבוע אחרון לתצוגה
    const week = [];
    for (let i = 6; i >= 0; i--) {
      const d = addDays(l.day, -i);
      if (d < u.created_day) { week.push({ day: d, dow: dowOf(d), s: 'none' }); continue; }
      const x = this.dayResult(u.id, d);
      week.push({ day: d, dow: dowOf(d), s: x.empty ? 'none' : x.ok ? 'ok' : i === 0 ? 'open' : 'fail' });
    }
    return {
      me: { email: u.email, gate: u.gate_key, remind_min: u.remind_min, remind_every: u.remind_every, quiet_min: u.quiet_min,
        pushCount: this.one('SELECT COUNT(*) AS c FROM subs WHERE user_id = ?', u.id).c },
      today: { day: l.day, dow: l.dow, hour: l.hour, min: l.min, checks: r.checks, locked: this.locked(u, l),
        tasks: r.tasks.map(t => ({ ...pubTask(t), ...(t.per_week ? { must: t.must, week_done: t.before + (r.checks[t.id] === 'done' ? 1 : 0) } : {}) })) },
      tasks: all.map(pubTask), week, ...this.streak(u)
    };
  }
  async vapid() {
    let v = this.kvGet('vapid');
    if (!v) {
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      v = JSON.stringify({ pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)), jwk: await crypto.subtle.exportKey('jwk', kp.privateKey) });
      this.kvSet('vapid', v);
    }
    return JSON.parse(v);
  }
  async sendPush(sub, msg) {
    const v = await this.vapid();
    const aud = new URL(sub.endpoint).origin;
    const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
    const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:luz@nimrodyaroker.workers.dev' })));
    const key = await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const sig = b64u(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + body)));
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: { authorization: `vapid t=${head}.${body}.${sig}, k=${v.pub}`, ttl: '1800', urgency: 'high', 'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream' },
      body: await encryptPayload(sub, JSON.stringify(msg))
    });
    if (res.status === 404 || res.status === 410) this.sql.exec('DELETE FROM subs WHERE endpoint = ?', sub.endpoint);
    return res.status;
  }
  async pushUser(uid, msg) {
    const subs = this.q('SELECT * FROM subs WHERE user_id = ?', uid);
    const out = [];
    for (const s of subs) { try { out.push(await this.sendPush(s, msg)); } catch (e) { console.error('push', e); out.push(0); } }
    return out;
  }
  async cron() {
    const l = local(), now = Date.now();
    for (const u of this.q('SELECT u.* FROM users u WHERE EXISTS (SELECT 1 FROM subs s WHERE s.user_id = u.id)')) {
      if (l.min >= u.quiet_min || l.min < Math.min(u.remind_min, 420)) continue;
      const r = this.dayResult(u.id, l.day);
      if (!r.open.length) continue;
      const late = r.open.filter(t => t.by_min != null && l.min >= t.by_min);
      const every = late.length ? Math.min(15, u.remind_every) : u.remind_every;
      if (!late.length && l.min < u.remind_min) continue;
      if (now - u.last_push < every * 60e3 - 60e3) continue;
      const names = (late.length ? late : r.open).slice(0, 3).map(t => t.title).join(', ');
      const msg = late.length
        ? { title: 'עבר הזמן', body: `${names} – היה צריך להיות גמור. קום ותעשה.` }
        : { title: `נשארו ${r.open.length} משימות`, body: `${names}. אני לא עוזב אותך עד שזה נגמר.` };
      this.sql.exec('UPDATE users SET last_push = ? WHERE id = ?', now, u.id);
      await this.pushUser(u.id, msg);
    }
  }

  // ---------- נתיבים ----------
  async handle(request) {
    const url = new URL(request.url), path = url.pathname, method = request.method;
    const ip = request.headers.get('cf-connecting-ip') || '';

    if (path === '/internal/cron' && url.hostname === 'internal') { await this.cron(); return json({ ok: true }); }

    // מצב לקיצור באייפון: locked / open. המפתח אקראי ואישי
    let m = path.match(/^\/api\/gate\/([A-Za-z0-9_-]{16,40})$/);
    if (m && method === 'GET') {
      if (this.limiter.over('gate:' + ip, 120, 60e3)) return text('open');
      this.limiter.add('gate:' + ip, 60e3);
      const u = this.one('SELECT * FROM users WHERE gate_key = ?', m[1]);
      return text(u && this.locked(u) ? 'locked' : 'open');
    }

    if (method !== 'GET' && method !== 'POST' && method !== 'PUT' && method !== 'DELETE') throw new HttpError(405, 'לא נתמך');
    if (this.limiter.over('all:' + ip, 300, 60e3)) throw new HttpError(429, 'יותר מדי בקשות. חכה רגע');
    this.limiter.add('all:' + ip, 60e3);
    let body = {};
    if (method === 'POST' || method === 'PUT') {
      const raw = await request.text();
      if (raw.length > 8000) bad('בקשה גדולה מדי');
      try { body = raw ? JSON.parse(raw) : {}; } catch { bad('בקשה לא תקינה'); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) bad('בקשה לא תקינה');
    }

    if (path === '/api/signup' && method === 'POST') {
      if (this.limiter.over('signup:' + ip, 5, 3600e3)) throw new HttpError(429, 'יותר מדי הרשמות. נסה מאוחר יותר');
      const email = norm(body.email, 120).toLowerCase(), pass = String(body.password ?? '');
      if (!EMAIL_RE.test(email)) bad('המייל לא נראה תקין');
      if (pass.length < MIN_PASS || pass.length > 200) bad(`סיסמה של לפחות ${MIN_PASS} תווים`);
      if (this.one('SELECT id FROM users WHERE email = ?', email)) bad('המייל הזה כבר רשום. נסה להתחבר');
      this.limiter.add('signup:' + ip, 3600e3);
      const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
      const l = local();
      this.sql.exec('INSERT INTO users (email, pass_hash, salt, gate_key, created, created_day) VALUES (?, ?, ?, ?, ?, ?)',
        email, await hashPassword(pass, salt), salt, randomId(18), Date.now(), l.day);
      const u = this.one('SELECT * FROM users WHERE email = ?', email);
      return json({ token: this.newSession(u.id) });
    }
    if (path === '/api/login' && method === 'POST') {
      const email = norm(body.email, 120).toLowerCase(), pass = String(body.password ?? '').slice(0, 200);
      const lk = 'login:' + email, ipk = 'loginip:' + ip;
      if (this.limiter.over(lk, 5, 15 * 60e3) || this.limiter.over(ipk, 20, 15 * 60e3)) {
        this.secLog('login_locked', email, ip);
        throw new HttpError(429, 'יותר מדי ניסיונות. נסה שוב בעוד רבע שעה');
      }
      const u = this.one('SELECT * FROM users WHERE email = ?', email);
      const ok = u && safeEqual(await hashPassword(pass, u.salt), u.pass_hash);
      if (!ok) { this.limiter.add(lk, 15 * 60e3); this.limiter.add(ipk, 15 * 60e3); this.secLog('login_fail', email, ip); bad('מייל או סיסמה לא נכונים'); }
      this.limiter.clear(lk);
      return json({ token: this.newSession(u.id) });
    }

    const u = this.auth(request);

    if (path === '/api/logout' && method === 'POST') {
      this.sql.exec('DELETE FROM sessions WHERE token = ?', (request.headers.get('authorization') || '').slice(7));
      return json({ ok: true });
    }
    if (path === '/api/state' && method === 'GET') return json(this.state(u));

    if (path === '/api/tasks' && method === 'POST') {
      const t = cleanTask(body);
      if (this.one('SELECT COUNT(*) AS c FROM tasks WHERE user_id = ? AND to_day IS NULL', u.id).c >= MAX_TASKS) bad('יותר מדי משימות');
      const maxSort = this.one('SELECT MAX(sort) AS s FROM tasks WHERE user_id = ?', u.id).s || 0;
      this.sql.exec('INSERT INTO tasks (id, user_id, title, kind, days, per_week, by_hour, by_min, sort, from_day, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        randomId(9), u.id, t.title, t.kind, t.days, t.per_week, t.by_hour, t.by_min, maxSort + 1, local().day, Date.now());
      return json(this.state(u));
    }
    m = path.match(/^\/api\/tasks\/([A-Za-z0-9_-]{6,20})$/);
    if (m) {
      const task = this.one('SELECT * FROM tasks WHERE id = ? AND user_id = ? AND to_day IS NULL', m[1], u.id);
      if (!task) throw new HttpError(404, 'המשימה לא נמצאה');
      const today = local().day;
      if (method === 'DELETE') {
        // ימים קודמים נשארים בהיסטוריה; מהיום המשימה לא קיימת
        if (task.from_day >= today) { this.sql.exec('DELETE FROM tasks WHERE id = ?', task.id); this.sql.exec('DELETE FROM checks WHERE task_id = ?', task.id); }
        else this.sql.exec('UPDATE tasks SET to_day = ? WHERE id = ?', today, task.id);
        return json(this.state(u));
      }
      if (method === 'PUT') {
        const t = cleanTask(body);
        if (task.from_day >= today || (t.kind === task.kind && t.days === task.days && t.per_week === (task.per_week ?? null))) {
          this.sql.exec('UPDATE tasks SET title = ?, kind = ?, days = ?, per_week = ?, by_hour = ?, by_min = ? WHERE id = ?', t.title, t.kind, t.days, t.per_week, t.by_hour, t.by_min, task.id);
        } else {
          // שינוי ימים/סוג חל מהיום והלאה, בלי לשנות את העבר
          const nid = randomId(9);
          this.sql.exec('UPDATE tasks SET to_day = ? WHERE id = ?', today, task.id);
          this.sql.exec('INSERT INTO tasks (id, user_id, title, kind, days, per_week, by_hour, by_min, sort, from_day, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            nid, u.id, t.title, t.kind, t.days, t.per_week, t.by_hour, t.by_min, task.sort, today, Date.now());
          this.sql.exec('UPDATE checks SET task_id = ? WHERE task_id = ? AND day = ?', nid, task.id, today);
        }
        return json(this.state(u));
      }
    }
    if (path === '/api/check' && method === 'POST') {
      const today = local().day, id = norm(body.task, 20);
      const task = this.tasksOn(u.id, today).find(t => t.id === id);
      if (!task) bad('המשימה לא להיום');
      const st = body.status;
      if (st === null) this.sql.exec('DELETE FROM checks WHERE task_id = ? AND day = ?', id, today);
      else if ((task.kind === 'do' && st === 'done') || (task.kind === 'dont' && st === 'broke'))
        this.sql.exec('INSERT INTO checks (task_id, user_id, day, status, t) VALUES (?, ?, ?, ?, ?) ON CONFLICT(task_id, day) DO UPDATE SET status = excluded.status, t = excluded.t', id, u.id, today, st, Date.now());
      else bad('סימון לא תקין');
      return json(this.state(u));
    }
    if (path === '/api/settings' && method === 'POST') {
      const rm = intIn(body.remind_min, 0, 1439, u.remind_min), qm = intIn(body.quiet_min, 0, 1440, u.quiet_min);
      if (qm <= rm) bad('שעת השקט צריכה להיות אחרי שעת ההתחלה');
      this.sql.exec('UPDATE users SET remind_min = ?, remind_every = ?, quiet_min = ? WHERE id = ?',
        rm, [15, 30, 60, 120].includes(Number(body.remind_every)) ? Number(body.remind_every) : u.remind_every, qm, u.id);
      return json(this.state(this.one('SELECT * FROM users WHERE id = ?', u.id)));
    }
    if (path === '/api/push/key' && method === 'GET') return json({ key: (await this.vapid()).pub });
    if (path === '/api/push/subscribe' && method === 'POST') {
      const s = body.sub || {}, endpoint = String(s.endpoint || ''), p = String(s.keys?.p256dh || ''), a = String(s.keys?.auth || '');
      let host = '';
      try { host = new URL(endpoint).hostname; } catch {}
      if (!endpoint.startsWith('https://') || endpoint.length > 600 || !/^[A-Za-z0-9_-]{80,100}$/.test(p) || !/^[A-Za-z0-9_-]{16,30}$/.test(a)) bad('הרשמה להתראות לא תקינה');
      if (!/(^|\.)(push\.apple\.com|googleapis\.com|mozilla\.com|mozaws\.net|notify\.windows\.com)$/.test(host)) bad('שירות התראות לא מוכר');
      if (this.one('SELECT COUNT(*) AS c FROM subs WHERE user_id = ?', u.id).c >= 6) this.sql.exec('DELETE FROM subs WHERE endpoint = (SELECT endpoint FROM subs WHERE user_id = ? ORDER BY created LIMIT 1)', u.id);
      this.sql.exec('INSERT INTO subs (endpoint, user_id, p256dh, auth, created) VALUES (?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth',
        endpoint, u.id, p, a, Date.now());
      return json({ ok: true });
    }
    if (path === '/api/push/test' && method === 'POST') {
      if (this.limiter.over('test:' + u.id, 5, 60e3)) throw new HttpError(429, 'חכה דקה');
      this.limiter.add('test:' + u.id, 60e3);
      const res = await this.pushUser(u.id, { title: 'Luz מחובר', body: 'ככה ייראו ההתראות. עכשיו – לעבודה.' });
      return json({ sent: res.filter(s => s >= 200 && s < 300).length });
    }
    if (path === '/api/gate/reset' && method === 'POST') {
      this.sql.exec('UPDATE users SET gate_key = ? WHERE id = ?', randomId(18), u.id);
      return json(this.state(this.one('SELECT * FROM users WHERE id = ?', u.id)));
    }
    if (path === '/api/password' && method === 'POST') {
      if (this.limiter.over('pw:' + u.id, 5, 15 * 60e3)) throw new HttpError(429, 'יותר מדי ניסיונות');
      const old = String(body.old ?? '').slice(0, 200), nw = String(body.password ?? '');
      if (!safeEqual(await hashPassword(old, u.salt), u.pass_hash)) { this.limiter.add('pw:' + u.id, 15 * 60e3); this.secLog('pw_fail', u.email, ip); bad('הסיסמה הנוכחית לא נכונה'); }
      if (nw.length < MIN_PASS || nw.length > 200) bad(`סיסמה של לפחות ${MIN_PASS} תווים`);
      const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
      this.sql.exec('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?', await hashPassword(nw, salt), salt, u.id);
      const token = (request.headers.get('authorization') || '').slice(7);
      this.sql.exec('DELETE FROM sessions WHERE user_id = ? AND token != ?', u.id, token);
      return json({ ok: true });
    }
    throw new HttpError(404, 'לא נמצא');
  }
}

function cleanTask(b) {
  const title = norm(b.title, 50);
  if (!title) bad('כתוב מה המשימה');
  const kind = b.kind === 'dont' ? 'dont' : 'do';
  const per_week = kind === 'do' && b.per_week != null && b.per_week !== '' ? intIn(b.per_week, 1, 6, null) : null;
  if (kind === 'do' && b.per_week != null && b.per_week !== '' && !per_week) bad('בחר כמה פעמים בשבוע');
  const days = per_week ? '0123456' : [...new Set(String(b.days ?? '').split('').filter(c => /[0-6]/.test(c)))].sort().join('');
  if (!days) bad('בחר לפחות יום אחד');
  let by_min = b.by_min === null || b.by_min === '' || b.by_min === undefined ? null : intIn(b.by_min, 0, 1439, -1);
  if (by_min === -1) bad('השעה לא תקינה');
  if (kind !== 'do') by_min = null;
  return { title, kind, days, per_week, by_min, by_hour: by_min == null ? null : Math.floor(by_min / 60) };
}
const pubTask = (t) => ({ id: t.id, title: t.title, kind: t.kind, days: t.days, per_week: t.per_week ?? null, by_min: t.by_min ?? null });
