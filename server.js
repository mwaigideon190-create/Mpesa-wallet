require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const E = process.env;
const crypto = require('crypto');

// FIX 1: accept the MPESA_-prefixed names too, so variables already added in Render work.
E.CONSUMER_KEY = E.CONSUMER_KEY || E.MPESA_CONSUMER_KEY;
E.CONSUMER_SECRET = E.CONSUMER_SECRET || E.MPESA_CONSUMER_SECRET;
E.PASSKEY = E.PASSKEY || E.MPESA_PASSKEY;
E.SHORTCODE = E.SHORTCODE || E.MPESA_SHORTCODE;

// Works out of the box: missing secrets are generated (set them in Render > Environment for stable logins).
if (!E.JWT_SECRET && E.MPESA_ENV === 'production') { console.error('JWT_SECRET is required in production'); process.exit(1); }
if (!E.JWT_SECRET) { E.JWT_SECRET = crypto.randomBytes(32).toString('hex'); console.warn('JWT_SECRET not set: using a temporary one, logins reset on restart.'); }
if (!E.CALLBACK_SECRET && E.MPESA_ENV === 'production') { console.error('CALLBACK_SECRET is required in production'); process.exit(1); }
if (!E.CALLBACK_SECRET) { E.CALLBACK_SECRET = crypto.randomBytes(16).toString('hex'); console.warn('CALLBACK_SECRET not set: using a temporary one.'); }
const BUNI = !!E.MPESA_TOKEN_URL; // KCB Buni mode is on when MPESA_TOKEN_URL is set
const mpesaConfigured = () => !!(E.CONSUMER_KEY && E.CONSUMER_SECRET && (BUNI || E.PASSKEY));
const mpesaReady = () => { if (!mpesaConfigured()) throw new Error('M-Pesa is not connected on this server yet. Add CONSUMER_KEY, CONSUMER_SECRET, PASSKEY and SHORTCODE in Render > Environment.'); };
const BASE = E.MPESA_BASE_URL || (E.MPESA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke');
const TOKEN_URL = E.MPESA_TOKEN_URL || `${BASE}/oauth/v1/generate?grant_type=client_credentials`; // e.g. https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials

// FIX 3: set DB_PATH to a persistent disk path (e.g. /var/data/wallet.db) so data survives restarts.
const fs = require('fs');
const DB_FILE = E.DB_PATH || (fs.existsSync('/var/data') ? '/var/data/wallet.db' : 'wallet.db');
if (E.RENDER && !DB_FILE.startsWith('/var/data')) console.warn('WARNING: database is not on a persistent disk. All data is lost on restart or deploy.');
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('busy_timeout = 5000');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0), created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS txs(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL, amount INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', checkout_id TEXT UNIQUE, conv_id TEXT UNIQUE,
  receipt TEXT, raw TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS ledger(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, tx_id INTEGER NOT NULL, entry TEXT NOT NULL,
  delta INTEGER NOT NULL, balance_after INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tx_id, entry));
`);

// Roles and account status (safe to run on an existing database).
const userCols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userCols.includes('role')) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
if (!userCols.includes('status')) db.exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'");
const txCols = db.prepare('PRAGMA table_info(txs)').all().map(c => c.name);
if (!txCols.includes('kes')) db.exec('ALTER TABLE txs ADD COLUMN kes INTEGER');
// Version 1: balances and amounts are USD cents (earlier versions stored KES). Converted once.
if (db.pragma('user_version', { simple: true }) < 1) {
  const r0 = Number(E.USD_KES_RATE || 129);
  db.prepare('UPDATE txs SET kes = amount WHERE kes IS NULL').run();
  db.prepare('UPDATE txs SET amount = ROUND(amount * 100.0 / ?)').run(r0);
  db.prepare('UPDATE users SET balance = ROUND(balance * 100.0 / ?)').run(r0);
  db.prepare('UPDATE ledger SET delta = ROUND(delta * 100.0 / ?), balance_after = ROUND(balance_after * 100.0 / ?)').run(r0, r0);
  db.pragma('user_version = 1');
}
db.exec(`CREATE INDEX IF NOT EXISTS idx_txs_user ON txs(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_txs_kind ON txs(kind, created_at);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON ledger(user_id, id DESC);`);
db.exec(`CREATE TABLE IF NOT EXISTS admin_log(
  id INTEGER PRIMARY KEY, admin_id INTEGER NOT NULL, action TEXT NOT NULL, target_id INTEGER, detail TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);

// ---- helpers ----
function normPhone(p) {
  p = String(p || '').replace(/[\s+-]/g, '');
  if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1);
  if (!/^254[17]\d{8}$/.test(p)) throw new Error('Invalid Kenyan phone number');
  return p;
}
// Wallet balances are USD cents. M-Pesa moves KES, converted at USD_KES_RATE with a spread (FX_SPREAD_PCT) either way.
const RATE = () => Number(E.USD_KES_RATE || 129), SPREAD = () => Number(E.FX_SPREAD_PCT || 1.5) / 100;
const MIN_USD = Number(E.MIN_USD || 2), MAX_USD = Number(E.MAX_USD || 1000);
const cents = (v, lo = MIN_USD, hi = MAX_USD) => { const n = Number(v); if (!Number.isFinite(n) || n < lo || n > hi) throw new Error(`Amount must be between $${lo} and $${hi}`); return Math.round(n * 100); };
const kesIn = (c) => Math.ceil(c / 100 * RATE() * (1 + SPREAD()));   // KES the customer pays for c cents
const kesOut = (c) => Math.floor(c / 100 * RATE() * (1 - SPREAD())); // KES the customer receives for c cents

// Move money on the ledger atomically. UNIQUE(tx_id, entry) makes it idempotent.
const post = db.transaction((userId, txId, entry, delta) => {
  const exists = db.prepare('SELECT 1 FROM ledger WHERE tx_id=? AND entry=?').get(txId, entry);
  if (exists) return false;
  const u = db.prepare('SELECT balance FROM users WHERE id=?').get(userId);
  const after = u.balance + delta;
  if (after < 0) throw new Error('Insufficient funds');
  db.prepare('UPDATE users SET balance=? WHERE id=?').run(after, userId);
  db.prepare('INSERT INTO ledger(user_id,tx_id,entry,delta,balance_after) VALUES(?,?,?,?,?)').run(userId, txId, entry, delta, after);
  return true;
});

// Developer/admin account is created from Render environment variables (never hardcode passwords in code).
function seedAdmin() {
  if (!E.ADMIN_EMAIL || !E.ADMIN_PASSWORD) return console.warn('ADMIN_EMAIL / ADMIN_PASSWORD not set: no admin account created.');
  try {
    if (E.ADMIN_PASSWORD.length < 8) throw new Error('ADMIN_PASSWORD must be at least 8 characters');
    const email = E.ADMIN_EMAIL.trim().toLowerCase();
    const phone = normPhone(E.ADMIN_PHONE);
    const hash = bcrypt.hashSync(E.ADMIN_PASSWORD, 10);
    const ex = db.prepare('SELECT id FROM users WHERE email=?').get(email);
    if (ex) db.prepare("UPDATE users SET pass_hash=?, role='admin', status='active' WHERE id=?").run(hash, ex.id);
    else db.prepare("INSERT INTO users(email,phone,pass_hash,role) VALUES(?,?,?,'admin')").run(email, phone, hash);
    console.log('Admin account ready:', email);
  } catch (e) { console.error('Admin seed failed:', e.message); }
}
seedAdmin();


// ---- Daraja client ----
let tok = { v: null, exp: 0 }, tokP = null;
function token() {
  if (tok.v && Date.now() < tok.exp) return Promise.resolve(tok.v);
  if (tokP) return tokP; // many requests at once share one token call
  tokP = (async () => {
    const basic = 'Basic ' + Buffer.from(`${E.CONSUMER_KEY}:${E.CONSUMER_SECRET}`).toString('base64');
    let r;
    try {
      r = await fetch(TOKEN_URL, { signal: AbortSignal.timeout(15000), ...(BUNI
        ? { method: 'POST', headers: { Authorization: basic, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' }
        : { headers: { Authorization: basic } }) });
    } catch { throw new Error((BUNI ? 'KCB Buni' : 'Daraja') + ' did not respond. Try again.'); }
    if (!r.ok) throw new Error((BUNI ? 'KCB Buni' : 'Daraja') + ' auth failed');
    const j = await r.json();
    const life = Number(j.expires_in) > 120 ? Number(j.expires_in) : 3000;
    tok = { v: j.access_token, exp: Date.now() + (life - 60) * 1000 };
    return tok.v;
  })().finally(() => { tokP = null; });
  return tokP;
}
// One place for every M-Pesa / KCB call: bearer token, 30s timeout, and one automatic retry with a fresh token if the old one was rejected (401).
async function api(url, body, who) {
  for (let i = 0; ; i++) {
    const bearer = await token();
    let r;
    try {
      r = await fetch(url, { method: 'POST', signal: AbortSignal.timeout(30000),
        headers: { Authorization: 'Bearer ' + bearer, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } catch { throw Object.assign(new Error('No response from ' + who), { unknown: true }); } // outcome unknown: money may have moved
    if (r.status === 401 && i === 0) { tok = { v: null, exp: 0 }; continue; }
    return r;
  }
}
async function daraja(path, body) {
  const r = await api(BASE + path, body, 'M-Pesa');
  const j = await r.json().catch(() => ({}));
  if (r.status >= 500) throw Object.assign(new Error(`M-Pesa error ${r.status}`), { unknown: true });
  if (!r.ok) throw new Error(j.errorMessage || `Daraja error ${r.status}`);
  return j;
}
// KCB Buni STK push (replaces Daraja for deposits when MPESA_TOKEN_URL is set)
async function buniStk(body) {
  const base = (E.KCB_BASE_URL || 'https://uat.buni.kcbgroup.com').replace(/\/$/, '');
  const r = await api(base + '/mm/api/request/1.0.0/stkpush', body, 'KCB');
  const j = await r.json().catch(() => ({}));
  console.log('buni stk response', r.status, JSON.stringify(j).slice(0, 500));
  if (!r.ok) throw new Error(j.errorMessage || j.message || `KCB error ${r.status}`);
  return j.response || j;
}
const cb = (p) => `${E.CALLBACK_BASE_URL || E.RENDER_EXTERNAL_URL}/mpesa/${p}/${E.CALLBACK_SECRET}`;

// KCB Buni Funds Transfer: KCB account -> M-Pesa number. Switched on with KCB_PAYOUTS=1.
// If KCB rejects a field, the full reply is in the logs ("buni transfer response"). Adjust without code changes using
// KCB_TRANSFER_EXTRA (JSON merged into the body), KCB_TRANSFER_PATH and KCB_COMPANY_CODE.
// A clear "no" from KCB (money did not move): friendly message, client is refunded.
function kcbRefusal(j, status) {
  const h = j.header || j;
  const why = String(h.statusDescription || h.statusMessage || j.errorMessage || j.message || j.error_description || '');
  if (/whitelist/i.test(why)) return new Error('Automatic M-Pesa payouts are waiting for KCB to approve this account. Use "Cash out (cash handed over)" and pay the client manually.');
  return new Error(why ? 'KCB rejected the transfer: ' + why.slice(0, 120) : `KCB rejected the transfer (${status})`);
}
async function buniTransfer(phone, kes, ref) {
  const base = (E.KCB_BASE_URL || 'https://uat.buni.kcbgroup.com').replace(/\/$/, '');
  const path = E.KCB_TRANSFER_PATH || '/fundstransfer/1.0.0/api/v1/transfer';
  let extra = {}; try { extra = JSON.parse(E.KCB_TRANSFER_EXTRA || '{}'); } catch { console.error('KCB_TRANSFER_EXTRA is not valid JSON'); }
  // Field list and limits taken from KCB's FundsTransferAPIService swagger (v1.0.0).
  // Still unconfirmed by KCB: transactionType 'MO' and beneficiaryBankCode 'MPESA' (from a community guide), and the phone format.
  const credit = E.KCB_PHONE_INTL === '1' ? String(phone) : '0' + String(phone).slice(3); // swagger caps creditAccountNumber at 10 chars
  const body = { companyCode: E.KCB_COMPANY_CODE || 'KE0010001', transactionType: E.KCB_TRANSFER_TYPE || 'MO',
    debitAccountNumber: String(E.KCB_ACCOUNT_NUMBER), creditAccountNumber: credit, debitAmount: Number(kes),
    paymentDetails: 'Wallet withdrawal', transactionReference: String(ref).slice(0, 12), currency: 'KES',
    beneficiaryDetails: 'WALLET CLIENT', beneficiaryBankCode: E.KCB_BENEFICIARY_BANK || 'MPESA', ...extra };
  console.log('buni transfer request', JSON.stringify(body));
  const r = await api(base + path, body, 'KCB');
  const j = await r.json().catch(() => ({}));
  console.log('buni transfer response', r.status, JSON.stringify(j).slice(0, 800));
  if (r.status >= 500) throw Object.assign(new Error(`KCB error ${r.status}`), { unknown: true });
  if (!r.ok) throw kcbRefusal(j, r.status);
  return j;
}
// Sends the payout and records the outcome. Daraja path unchanged; Buni answers straight away (no callback).
async function sendPayout(u, txId, kes) {
  if (BUNI) {
    const j = await buniTransfer(u.phone, kes, ('WD' + txId + Date.now().toString(36)));
    const h = j.header || j;
    const code = h.statusCode == null ? null : String(h.statusCode);
    if (code !== null && code !== '0') throw kcbRefusal(j, 200); // KCB: any code except 0 means it was not submitted
    if (code === '0') {
      db.prepare("UPDATE txs SET status='success', receipt=?, raw=? WHERE id=?").run(h.retrievalRefNumber || h.messageID || null, JSON.stringify(j), txId);
      return 'done';
    }
    db.prepare("UPDATE txs SET status='review', raw=? WHERE id=?").run(JSON.stringify(j), txId);
    throw Object.assign(new Error('KCB did not confirm the transfer. Do not retry: check the KCB statement, then settle it in Transactions.'), { held: true });
  }
  const r = await daraja('/mpesa/b2c/v1/paymentrequest', {
    InitiatorName: E.INITIATOR_NAME, SecurityCredential: E.SECURITY_CREDENTIAL,
    CommandID: 'BusinessPayment', Amount: kes, PartyA: E.B2C_SHORTCODE || E.SHORTCODE, PartyB: u.phone,
    Remarks: 'Wallet withdrawal', QueueTimeOutURL: cb('b2c-timeout'), ResultURL: cb('b2c-result'), Occasion: 'Withdrawal' });
  if (r.ResponseCode !== '0') throw new Error(r.ResponseDescription || 'Rejected by M-Pesa');
  db.prepare('UPDATE txs SET conv_id=? WHERE id=?').run(r.OriginatorConversationID, txId);
  return 'queued';
}

// Payout (B2C) needs its own settings. Fail early with a clear message instead of a failed payout.
const b2cReady = () => {
  mpesaReady();
  if (BUNI) {
    if (E.KCB_PAYOUTS !== '1') throw new Error('Automatic M-Pesa payouts are not available yet. Use "Cash out (cash handed over)" and pay the client manually.');
    if (!E.KCB_ACCOUNT_NUMBER) throw new Error('KCB_ACCOUNT_NUMBER is not set in Render > Environment');
    return;
  }
  if (!E.INITIATOR_NAME || !E.SECURITY_CREDENTIAL) throw new Error('M-Pesa payouts are not set up: add INITIATOR_NAME and SECURITY_CREDENTIAL in Render > Environment.');
  if (!E.B2C_SHORTCODE && String(E.SHORTCODE) === '174379') throw new Error('M-Pesa payouts need a B2C shortcode: add B2C_SHORTCODE in Render > Environment (the 600... test shortcode from your Daraja app). 174379 only works for deposits.');
};

// ---- app ----
const app = express();
app.disable('x-powered-by');

// FIX 2: Render runs behind a proxy. Without this, all visitors share one rate-limit counter (429 errors).
app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (E.CORS_ORIGIN) {
    res.set({ 'Access-Control-Allow-Origin': E.CORS_ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=15552000; includeSubDomains',
    'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()' });
  next();
});
app.use(['/auth', '/wallet', '/admin'], (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }); // never cache money or login responses
const adminIps = (E.ADMIN_IPS || '').split(',').map(x => x.trim()).filter(Boolean); // optional allowlist
app.use(['/admin', '/admin.html'], (req, res, next) => (adminIps.length && !adminIps.includes(req.ip)) ? res.sendStatus(404) : next());
app.use(express.json({ limit: '20kb' }));
app.use(express.static('public'));
app.use(rateLimit({ windowMs: 60_000, limit: 60 }));
const strict = rateLimit({ windowMs: 15 * 60_000, limit: 10 });

const auth = (req, res, next) => {
  try {
    req.uid = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), E.JWT_SECRET, { algorithms: ['HS256'] }).uid;
    const u = db.prepare('SELECT role, status FROM users WHERE id=?').get(req.uid);
    if (!u) throw new Error('no user');
    if (u.status !== 'active') return res.status(403).json({ error: 'Account suspended' });
    req.role = u.role;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
};
const adminOnly = (req, res, next) => req.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });
// ---- Fraud / abuse guards ----
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10); // makes "unknown email" take as long as "wrong password"
const fails = new Map(); // key -> { n, until }: 5 wrong passwords locks that login for 15 minutes
const lockCheck = (key) => { const f = fails.get(key); if (f && f.until > Date.now()) throw new Error('Too many wrong attempts. Try again in 15 minutes.'); };
const lockFail = (key) => {
  const f = fails.get(key) || { n: 0, until: 0 };
  if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; }
  if (++f.n >= 5) { f.until = Date.now() + 15 * 60_000; console.warn('SECURITY: locked after repeated wrong passwords:', key); }
  if (fails.size > 5000) fails.clear();
  fails.set(key, f);
};
const lockClear = (key) => fails.delete(key);
const sameSecret = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const inFlight = new Set(); // one withdrawal at a time per user (stops double-tap and race attacks)
const WD_DAILY_USD = Number(E.WITHDRAW_DAILY_USD || 500), WD_PER_HOUR = Number(E.WITHDRAW_PER_HOUR || 3);
const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { res.status(400).json({ error: e.message }); } };

app.get('/health', (req, res) => res.json({ ok: true, mpesa: mpesaConfigured() }));

// Checks the Daraja keys by requesting an access token from TOKEN_URL.
app.get('/health/mpesa', async (req, res) => {
  try { mpesaReady(); tok = { v: null, exp: 0 }; await token(); res.json({ ok: true, endpoint: TOKEN_URL }); }
  catch (e) { res.status(503).json({ ok: false, error: e.message, endpoint: TOKEN_URL }); }
});

const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const mask = (p) => '0' + p.slice(3, 6) + ' *** ' + p.slice(-3);

app.post('/auth/register', strict, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!emailOk(email)) throw new Error('Enter a valid email address');
  const pw = String(req.body.password || '');
  if (pw.length < 8) throw new Error('Password must be at least 8 characters');
  const phone = normPhone(req.body.phone);
  const hash = await bcrypt.hash(pw, 10);
  try { db.prepare('INSERT INTO users(email,phone,pass_hash) VALUES(?,?,?)').run(email, phone, hash); }
  catch { throw new Error('This email or phone number already has an account'); }
  res.json({ ok: true });
}));

app.post('/auth/login', strict, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), key = 'login:' + email;
  lockCheck(key);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  const ok = await bcrypt.compare(String(req.body.password || ''), u ? u.pass_hash : DUMMY_HASH);
  if (!u || !ok) { lockFail(key); console.warn('SECURITY: failed login', email, req.ip); throw new Error('Wrong email or password'); }
  lockClear(key);
