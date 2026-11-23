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
  if (u.status !== 'active') throw new Error('Account suspended. Contact support.');
  res.json({ token: jwt.sign({ uid: u.id }, E.JWT_SECRET, { expiresIn: '1h' }), role: u.role });
}));

app.get('/wallet', auth, wrap(async (req, res) => {
  const u = db.prepare('SELECT email, phone, balance FROM users WHERE id=?').get(req.uid);
  res.json({ email: u.email, phone_masked: mask(u.phone), balance_usd: u.balance / 100, rate_kes_per_usd: RATE(), buy_kes: RATE() * (1 + SPREAD()), sell_kes: RATE() * (1 - SPREAD()), min_usd: MIN_USD, max_usd: MAX_USD });
}));

app.get('/wallet/transactions', auth, wrap(async (req, res) => {
  res.json(db.prepare('SELECT id,kind,amount/100.0 AS amount,kes,status,receipt,created_at FROM txs WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.uid));
}));

app.get('/wallet/tx/:id', auth, wrap(async (req, res) => {
  const t = db.prepare('SELECT status, receipt, kes, kind, json_extract(raw,\'$.ResultDesc\') AS reason FROM txs WHERE id=? AND user_id=?').get(Number(req.params.id), req.uid);
  if (!t) throw new Error('Transaction not found');
  res.json({ status: t.status, receipt: t.receipt, kes: t.kes, kind: t.kind, reason: t.reason });
}));

// Add money: STK Push to the user's own registered phone. The customer enters USD and pays the KES equivalent.
app.post('/wallet/topup', auth, strict, wrap(async (req, res) => {
  const c = cents(req.body.usd), amount = kesIn(c); // c = USD cents credited, amount = KES charged
  if (amount > 150000) throw new Error('That is above the M-Pesa limit for one payment');
  mpesaReady();
  const u = db.prepare('SELECT phone FROM users WHERE id=?').get(req.uid);
  const ts = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  if (BUNI && !E.KCB_ACCOUNT_NUMBER) throw new Error('KCB_ACCOUNT_NUMBER is not set in Render > Environment');
  const r = BUNI
    ? await buniStk({ phoneNumber: String(u.phone), amount: String(amount), invoiceNumber: String(E.KCB_ACCOUNT_NUMBER) + '-WALLET',
        ...(E.KCB_SHARED_SHORTCODE === '1' ? { sharedShortCode: true, orgShortCode: String(E.SHORTCODE), orgPassKey: '' } : {}),
        callbackUrl: cb('stk-callback'), transactionDescription: 'Wallet top-up' })
    : await daraja('/mpesa/stkpush/v1/processrequest', {
    BusinessShortCode: E.SHORTCODE,
    Password: Buffer.from(E.SHORTCODE + E.PASSKEY + ts).toString('base64'),
    Timestamp: ts, TransactionType: 'CustomerPayBillOnline', Amount: amount,
    PartyA: u.phone, PartyB: E.SHORTCODE, PhoneNumber: u.phone, CallBackURL: cb('stk-callback'),
    AccountReference: 'Wallet', TransactionDesc: 'Wallet top-up' });
  if (String(r.ResponseCode) !== '0' || !r.CheckoutRequestID) throw new Error(r.ResponseDescription || r.CustomerMessage || 'STK push failed');
  const txId = db.prepare("INSERT INTO txs(user_id,kind,amount,kes,checkout_id) VALUES(?,'topup',?,?,?)").run(req.uid, c, amount, r.CheckoutRequestID).lastInsertRowid;
  res.json({ message: 'Enter your M-Pesa PIN on your phone', id: txId, kes: amount, checkout_id: r.CheckoutRequestID });
}));

// Withdraw to M-Pesa (B2C): debit first, refund if it fails
app.post('/wallet/withdraw', auth, strict, wrap(async (req, res) => {
  const amount = cents(req.body.usd), kes = kesOut(amount); // amount = USD cents debited, kes = M-Pesa payout
  if (kes < 10 || kes > 150000) throw new Error('That amount cannot be sent through M-Pesa');
  b2cReady();
  if (inFlight.has(req.uid)) throw new Error('A withdrawal is already in progress. Please wait a moment.');
  inFlight.add(req.uid); res.on('close', () => inFlight.delete(req.uid));
  const wk = 'wd:' + req.uid; lockCheck(wk);
  const u = db.prepare('SELECT phone, pass_hash FROM users WHERE id=?').get(req.uid);
  if (!(await bcrypt.compare(String(req.body.password || ''), u.pass_hash))) { lockFail(wk); console.warn('SECURITY: wrong password on withdraw, user', req.uid, req.ip); throw new Error('Wrong password. Withdrawal not started.'); }
  lockClear(wk);
  if (db.prepare("SELECT 1 FROM txs WHERE user_id=? AND kind='withdraw' AND status='review'").get(req.uid)) throw new Error('You have a withdrawal under review. Support will clear it before the next one.');
  const day = db.prepare("SELECT COALESCE(SUM(amount),0) AS s FROM txs WHERE user_id=? AND kind='withdraw' AND status!='failed' AND created_at > datetime('now','-1 day')").get(req.uid).s;
  if (day + amount > WD_DAILY_USD * 100) { console.warn('SECURITY: daily withdrawal cap hit, user', req.uid); throw new Error(`Daily withdrawal limit is $${WD_DAILY_USD}. Try again later or contact support.`); }
  const hr = db.prepare("SELECT COUNT(*) AS n FROM txs WHERE user_id=? AND kind='withdraw' AND status!='failed' AND created_at > datetime('now','-1 hour')").get(req.uid).n;
  if (hr >= WD_PER_HOUR) { console.warn('SECURITY: withdrawal rate cap hit, user', req.uid); throw new Error('Too many withdrawals in the last hour. Please try again later.'); }
  const txId = db.prepare("INSERT INTO txs(user_id,kind,amount,kes) VALUES(?,'withdraw',?,?)").run(req.uid, amount, kes).lastInsertRowid;
  try { post(req.uid, txId, 'debit', -amount); }
  catch (e) { db.prepare("UPDATE txs SET status='failed' WHERE id=?").run(txId); throw e; }
  try {
    const st = await sendPayout(u, txId, kes);
    res.json({ message: st === 'done' ? 'Withdrawal sent to your M-Pesa' : 'Withdrawal processing', tx_id: txId });
  } catch (e) {
    if (e.unknown) { // do NOT refund: the payout may have gone through. An admin resolves it from the statement.
      db.prepare("UPDATE txs SET status='review' WHERE id=?").run(txId);
      throw new Error('Withdrawal status unknown. Do not retry: support will confirm it shortly.');
    }
    if (e.held) throw e;
    post(req.uid, txId, 'refund', amount);
    db.prepare("UPDATE txs SET status='failed' WHERE id=?").run(txId);
    throw e;
  }
}));

// ---- Admin / agent (developer) routes ----
const audit = (adminId, action, targetId, detail) =>
  db.prepare('INSERT INTO admin_log(admin_id,action,target_id,detail) VALUES(?,?,?,?)').run(adminId, action, targetId || null, detail || '');

app.get('/admin/summary', auth, adminOnly, wrap(async (req, res) => {
  const s = db.prepare("SELECT COUNT(*) AS users, COALESCE(SUM(balance),0) AS total_balance FROM users WHERE role!='treasury'").get();
  s.persistent = DB_FILE.startsWith('/var/data') || E.DB_PERSISTENT === '1'; s.on_render = !!E.RENDER; s.treasury = treasuryBal(); s.win_chance_pct = Math.round(winChance() * 100); s.target = G.target;
  const t = db.prepare(`SELECT
    COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) AS pending,
    COALESCE(SUM(CASE WHEN status='success' AND date(created_at)=date('now') AND kind IN ('topup','agent_in') THEN amount END),0) AS in_today,
    COALESCE(SUM(CASE WHEN status='success' AND date(created_at)=date('now') AND kind IN ('withdraw','agent_out') THEN amount END),0) AS out_today
    FROM txs`).get();
  res.json({ ...s, ...t });
}));

// Download a copy of the whole database (balances, users, Treasury). Keep copies somewhere safe.
app.get('/admin/backup', auth, adminOnly, async (req, res) => {
  try {
    const f = `/tmp/wallet-backup-${Date.now()}.db`;
    await db.backup(f);
    audit(req.uid, 'backup', null, 'database downloaded');
    res.download(f, 'wallet-backup.db', () => fs.unlink(f, () => {}));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/users', auth, adminOnly, wrap(async (req, res) => {
  const q = '%' + String(req.query.q || '').trim().toLowerCase() + '%';
  res.json(db.prepare("SELECT id,email,phone,balance,role,status,created_at FROM users WHERE role!='treasury' AND (lower(email) LIKE ? OR phone LIKE ?) ORDER BY id DESC LIMIT 200").all(q, q));
}));

app.post('/admin/users/:id/status', auth, adminOnly, wrap(async (req, res) => {
  const id = Number(req.params.id), st = req.body.status;
  if (!['active', 'suspended'].includes(st)) throw new Error('Invalid status');
  const u = db.prepare('SELECT role FROM users WHERE id=?').get(id);
  if (!u) throw new Error('User not found');
  if (u.role !== 'user') throw new Error('Cannot change an admin or system account');
  db.prepare('UPDATE users SET status=? WHERE id=?').run(st, id);
  audit(req.uid, 'status', id, st);
  res.json({ ok: true });
}));

app.post('/admin/users/:id/reset-password', auth, adminOnly, wrap(async (req, res) => {
  const id = Number(req.params.id), pw = String(req.body.password || '');
  if (pw.length < 8) throw new Error('Password must be at least 8 characters');
  const u = db.prepare('SELECT role FROM users WHERE id=?').get(id);
  if (!u) throw new Error('User not found');
  if (u.role !== 'user') throw new Error('Cannot reset an admin or system account password');
  db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(await bcrypt.hash(pw, 10), id);
  audit(req.uid, 'reset_password', id, '');
  res.json({ ok: true });
}));

app.get('/admin/transactions', auth, adminOnly, wrap(async (req, res) => {
  res.json(db.prepare(`SELECT t.id,t.kind,t.amount,t.status,t.receipt,t.created_at,u.email,json_extract(t.raw,'$.ResultDesc') AS reason FROM txs t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 100`).all());
}));

app.get('/admin/log', auth, adminOnly, wrap(async (req, res) => {
  res.json(db.prepare('SELECT l.id,l.action,l.target_id,l.detail,l.created_at,a.email AS admin FROM admin_log l JOIN users a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 100').all());
}));

// Settle a stuck top-up/withdrawal after checking the M-Pesa statement.
app.post('/admin/transactions/:id/resolve', auth, adminOnly, wrap(async (req, res) => {
  const id = Number(req.params.id), outcome = req.body.outcome, receipt = String(req.body.receipt || '').slice(0, 40);
  if (!['success', 'failed'].includes(outcome)) throw new Error('Outcome must be success or failed');
  db.transaction(() => {
    const t = db.prepare('SELECT * FROM txs WHERE id=?').get(id);
    if (!t) throw new Error('Transaction not found');
    if (!['topup', 'withdraw'].includes(t.kind)) throw new Error('Only top-ups and withdrawals can be resolved');
    if (!['pending', 'review'].includes(t.status)) throw new Error('Transaction is already settled');
    if (t.kind === 'topup' && outcome === 'success') post(t.user_id, t.id, 'credit', t.amount);
    if (t.kind === 'withdraw' && outcome === 'failed') post(t.user_id, t.id, 'refund', t.amount);
    db.prepare("UPDATE txs SET status=?, receipt=COALESCE(NULLIF(?,''),receipt) WHERE id=?").run(outcome, receipt, id);
    audit(req.uid, 'resolve', t.user_id, `tx ${id} ${t.kind} $${t.amount / 100} -> ${outcome} ${receipt}`);
  })();
  res.json({ ok: true });
}));

// Agent cash-in (customer hands you cash, wallet is credited) and cash-out (you hand cash, wallet is debited).
const agentMove = (kind) => wrap(async (req, res) => {
  const perMove = Number(E.AGENT_MAX_PER_MOVE || 500), perDay = Number(E.AGENT_MAX_PER_DAY || 2000); // USD
  const amount = cents(req.body.amount, Number(E.AGENT_MIN_USD || 0.01), perMove); // USD cents
  const used = db.prepare("SELECT COALESCE(SUM(amount),0) AS s FROM txs WHERE kind IN ('agent_in','agent_out') AND date(created_at)=date('now')").get().s;
  if (used + amount > perDay * 100) throw new Error('Daily agent limit reached');
  const phone = normPhone(req.body.phone);
  const u = db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
  if (!u) throw new Error('No account with that phone number');
  const note = String(req.body.note || '').slice(0, 100);
  db.transaction(() => {
    const txId = db.prepare("INSERT INTO txs(user_id,kind,amount,status) VALUES(?,?,?,'success')").run(u.id, kind, amount).lastInsertRowid;
    post(u.id, txId, kind === 'agent_in' ? 'credit' : 'debit', kind === 'agent_in' ? amount : -amount);
    audit(req.uid, kind, u.id, `$${amount / 100} ${note}`);
  })();
  res.json({ ok: true });
});
// Admin cash-out to M-Pesa: debit the client's wallet, then send the real money to the client's registered M-Pesa number (B2C).
// Same safety as a client withdrawal: debited first, refunded if M-Pesa rejects it, held for review if the outcome is unknown.
app.post('/admin/agent/cash-out-mpesa', auth, adminOnly, wrap(async (req, res) => {
  const amount = cents(req.body.amount, Number(E.AGENT_MIN_USD || 0.01), Number(E.AGENT_MAX_PER_MOVE || 500)); // USD cents
  const u = db.prepare('SELECT id, phone FROM users WHERE phone=? AND role!=\'treasury\'').get(normPhone(req.body.phone));
  if (!u) throw new Error('No client account with that phone number');
  const kes = kesOut(amount);
  if (kes < 10 || kes > 150000) throw new Error('That amount cannot be sent through M-Pesa');
  b2cReady();
  const txId = db.prepare("INSERT INTO txs(user_id,kind,amount,kes) VALUES(?,'withdraw',?,?)").run(u.id, amount, kes).lastInsertRowid;
  try { post(u.id, txId, 'debit', -amount); }
  catch (e) { db.prepare("UPDATE txs SET status='failed' WHERE id=?").run(txId); throw e; }
  audit(req.uid, 'cash_out_mpesa', u.id, `$${amount / 100} = KES ${kes} to ${u.phone}, tx ${txId}, ${String(req.body.note || '').slice(0, 100)}`);
  try {
    const st = await sendPayout(u, txId, kes);
    res.json({ ok: true, tx_id: txId, kes, message: st === 'done' ? "Sent to the client's M-Pesa." : 'Sent to M-Pesa. Check Transactions for the result.' });
  } catch (e) {
    if (e.unknown) {
      db.prepare("UPDATE txs SET status='review' WHERE id=?").run(txId);
      throw new Error('M-Pesa did not answer. Do not retry: check the statement, then settle it in Transactions.');
    }
    if (e.held) throw e;
    post(u.id, txId, 'refund', amount);
    db.prepare("UPDATE txs SET status='failed' WHERE id=?").run(txId);
    throw e;
  }
}));
app.post('/admin/agent/cash-in', auth, adminOnly, agentMove('agent_in'));
app.post('/admin/agent/cash-out', auth, adminOnly, agentMove('agent_out'));

// Admin transfer. Every transfer is real: the sender goes down and the receiver goes up by the same amount, in one atomic step.
// "from" and "to" are each a client phone number OR the word "treasury" (the Tradecoin house account). Supported:
//   account -> account, treasury -> account, account -> treasury.  (treasury -> treasury is refused.)
// Money only enters the system from outside through M-Pesa top-ups, agent cash-in, or "Add reserve" (money you really put in).
app.post('/admin/transfer', auth, adminOnly, wrap(async (req, res) => {
  const amount = cents(req.body.amount, 0.01, Number(E.TRANSFER_MAX_USD || 1000)); // USD cents
  const note = String(req.body.note || '').trim().slice(0, 100);
  if (!note) throw new Error('A reason is required');
  const party = (v, label) => {
    const x = String(v || '').trim();
    if (x.toLowerCase() === 'treasury') return db.prepare('SELECT id, role, email FROM users WHERE id=?').get(TID());
    const u = db.prepare('SELECT id, role, email FROM users WHERE phone=?').get(normPhone(x));
    if (!u) throw new Error(`No account with the ${label} phone number`);
    if (u.role === 'treasury') throw new Error('Type "treasury" to use the Treasury');
    return u;
  };
  const a = party(req.body.from, 'sender'), b = party(req.body.to, 'receiver');
  if (a.id === b.id) throw new Error('Choose two different accounts');
  db.transaction(() => {
    if (a.role === 'treasury' && treasuryBal() - amount < openPayouts()) throw new Error('Not enough free funds: open game bets must stay covered');
    const outKind = a.role === 'treasury' ? 'treasury_out' : 'transfer_out', inKind = b.role === 'treasury' ? 'treasury_in' : 'transfer_in';
    const out = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,?,?,'success',?)").run(a.id, outKind, amount, note).lastInsertRowid;
    const inn = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,?,?,'success',?)").run(b.id, inKind, amount, note).lastInsertRowid;
    post(a.id, out, 'debit', -amount);   // throws 'Insufficient funds' and rolls everything back
    post(b.id, inn, 'credit', amount);
    audit(req.uid, 'transfer', a.id, `$${amount / 100} ${a.email} -> ${b.email}: ${note}`);
  })();
  res.json({ ok: true });
}));

// ---- Tradecoin game ----
// Disclosed rules: pick UP or DOWN for a fixed round. A house fee is taken from every stake. Win = 2x the stake after the fee,
// tie = stake after fee returned, loss = stake kept by the Treasury. The price is an independent random walk: it never reacts to bets or balances.
db.exec(`CREATE TABLE IF NOT EXISTS game_ticks(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, price INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS game_bets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, side TEXT NOT NULL, stake INTEGER NOT NULL, fee INTEGER NOT NULL,
  entry INTEGER NOT NULL, exit_price INTEGER, status TEXT NOT NULL DEFAULT 'open', payout INTEGER NOT NULL DEFAULT 0, settle_at INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
const G = { fee: Number(E.GAME_FEE_PCT || 5) / 100, sec: Number(E.GAME_ROUND_SEC || 30), min: Number(E.GAME_MIN_USD || 0.2), max: Number(E.GAME_MAX_USD || 100), lossLimit: Number(E.GAME_DAILY_LOSS_USD || 200),
  mult: Number(E.GAME_WIN_MULT || 2), target: Math.round(Number(E.GAME_TARGET_USD || 150) * 100), lo: Number(E.GAME_WIN_PCT_LOW || 5) / 100, hi: Number(E.GAME_WIN_PCT_HIGH || 29) / 100 };
if (!db.prepare('PRAGMA table_info(game_bets)').all().some(c => c.name === 'win_chance')) db.exec('ALTER TABLE game_bets ADD COLUMN win_chance REAL');
// The Treasury is a house account that belongs to no client. It cannot log in; the admin moves its money from the admin page.
if (!db.prepare("SELECT 1 FROM users WHERE role='treasury'").get())
  db.prepare("INSERT INTO users(email,phone,pass_hash,role) VALUES('treasury@system.local','254000000000',?,'treasury')").run(bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10));
const TID = () => db.prepare("SELECT id FROM users WHERE role='treasury'").get().id;
const treasuryBal = () => db.prepare('SELECT balance FROM users WHERE id=?').get(TID()).balance;
const openPayouts = () => db.prepare(`SELECT COALESCE(SUM((stake-fee)*${G.mult}),0) AS s FROM game_bets WHERE status='open'`).get().s;
// Win chance depends only on the Treasury balance and is shown to every client. It is stored on each bet when the bet is placed.
function winChance() { return treasuryBal() >= G.target ? G.hi : G.lo; }
// Version 2: the coin used to start at $100. It now starts at $0 and stays closed until the admin starts it.
if (db.pragma('user_version', { simple: true }) < 2) {
  db.transaction(() => {
    for (const b of db.prepare("SELECT * FROM game_bets WHERE status='open'").all()) { // void open rounds: stake goes back to the player
      const tx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'game_refund',?,'success',?)").run(b.user_id, b.stake, 'TRADECOIN-VOID-' + b.id).lastInsertRowid;
      post(TID(), tx, 'house_out', -b.stake); post(b.user_id, tx, 'credit', b.stake);
      db.prepare("UPDATE game_bets SET status='tie', exit_price=entry, payout=stake WHERE id=?").run(b.id);
    }
    db.prepare('DELETE FROM game_ticks').run();
  })();
  db.pragma('user_version = 2');
}
let gPrice = (db.prepare('SELECT price FROM game_ticks ORDER BY id DESC LIMIT 1').get() || { price: 0 }).price; // $0.00 = closed
const rnd = () => crypto.randomInt(1, 1e9) / 1e9;
function settleDue() {
  const due = db.prepare("SELECT * FROM game_bets WHERE status='open' AND settle_at<=?").all(Date.now());
  for (const b of due) {
    try {
      db.transaction(() => {
        const n = b.stake - b.fee, t = TID();
        const win = rnd() < (b.win_chance || G.lo), tie = false;
        const pay = win ? Math.round(G.mult * n) : 0;
        if (pay > 0) {
          const tx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,?,?,'success',?)").run(b.user_id, win ? 'game_win' : 'game_refund', pay, 'TRADECOIN-' + b.id).lastInsertRowid;
          const short = pay - treasuryBal();
          if (short > 0) { const ctx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'house_cover',?,'success',?)").run(t, short, 'TRADECOIN-COVER-' + b.id).lastInsertRowid; post(t, ctx, 'credit', short); }
          post(t, tx, 'house_out', -pay); post(b.user_id, tx, 'credit', pay);
        }
        db.prepare('UPDATE game_bets SET status=?, exit_price=?, payout=? WHERE id=?').run(win ? 'won' : tie ? 'tie' : 'lost', gPrice, pay, b.id);
      })();
    } catch (e) { console.error('settle', b.id, e.message); }
  }
}
function gTick() { settleDue(); }
gTick(); setInterval(gTick, 3000);

app.get('/game/state', auth, wrap(async (req, res) => {
  const ticks = db.prepare('SELECT ts AS t, price AS p FROM game_ticks ORDER BY id DESC LIMIT 120').all().reverse().map(x => ({ t: x.t, p: x.p / 100 }));
  const bets = db.prepare('SELECT id,side,stake/100.0 AS stake,entry/100.0 AS entry,exit_price/100.0 AS exit,status,payout/100.0 AS payout,settle_at FROM game_bets WHERE user_id=? ORDER BY id DESC LIMIT 10').all(req.uid);
  const balance = db.prepare('SELECT balance FROM users WHERE id=?').get(req.uid).balance / 100;
  res.json({ open: true, reserve: treasuryBal() / 100, target: G.target / 100, win_chance_pct: Math.round(winChance() * 100), ticks, bets, balance, now: Date.now(),
    rules: { fee_pct: G.fee * 100, round_sec: G.sec, min_usd: G.min, max_usd: G.max, loss_limit_usd: G.lossLimit, win_multiple: G.mult * (1 - G.fee), chance_low_pct: Math.round(G.lo * 100), chance_high_pct: Math.round(G.hi * 100), expected_back_per_100: Math.round(winChance() * G.mult * (1 - G.fee) * 10000) / 100 } });
}));

app.post('/game/bet', auth, wrap(async (req, res) => {
  if (req.role === 'treasury') throw new Error('The Treasury account cannot play');
  if (req.body.confirm18 !== true) throw new Error('Please confirm you are 18 or older and understand this is a game of chance');
  const side = 'chance';
  const stake = cents(req.body.stake, G.min, G.max), fee = Math.round(stake * G.fee), n = stake - fee;
  const lost = db.prepare("SELECT COALESCE(SUM(stake)-SUM(payout),0) AS l FROM game_bets WHERE user_id=? AND date(created_at)=date('now')").get(req.uid).l;
  if (lost + stake > G.lossLimit * 100) throw new Error('Daily loss limit reached. Please come back tomorrow.');
  db.transaction(() => {
    const t = TID();
    const chance = winChance();
    if (Number(req.body.chance_pct) !== Math.round(chance * 100)) throw new Error('The win chance is now ' + Math.round(chance * 100) + '%. Please check it and place your bet again.');
    const tx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'game_stake',?,'success','TRADECOIN')").run(req.uid, stake).lastInsertRowid;
    post(req.uid, tx, 'debit', -stake); post(t, tx, 'house_in', stake);
    db.prepare('INSERT INTO game_bets(user_id,side,stake,fee,entry,settle_at,win_chance) VALUES(?,?,?,?,?,?,?)').run(req.uid, side, stake, fee, 0, Date.now() + G.sec * 1000, chance);
  })();
  res.json({ ok: true });
}));

// ---- Tradecoin chart trading: two independent markets (demo = practice money, live = real wallet money). The admin steers either or both. ----
// Rules: a trade multiplies its stake by a stepping multiplier (SEQ). A Buy wins while the value is above its entry line, a Sell while below.
// The multiplied stake is the profit, otherwise the loss (never more than stake + remaining balance). A 35% commission is added to every stake
// and goes to that market's admin transfer pot. Live trades move real wallet money through the Treasury account on the ledger.
const SEQ = [1.0, 1.01, 1.5, 1.6, 1.7, 1.8, 2.5, 2, 2.3, 2.9, 4.5, 3.0, 2.0, 1.6, 1.4, 1.09, 1.05, 3.04, 1.03, 1.6, 1.9, 3.0, 5.0], SN = SEQ.length, SBASE = 45, SBAND = 1, TSC = .5, XN = 19;
const MK_FEE = Number(E.MK_FEE_PCT || 35) / 100, MK_MIN = Number(E.MK_MIN_USD || 0.2), MK_MAX = Number(E.MK_MAX_USD || 100), MK_DEMO0 = 1000, MK_OPEN_MAX = 20;
db.exec(`CREATE TABLE IF NOT EXISTS mk_trades(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, mkt TEXT NOT NULL, dir INTEGER NOT NULL, stake INTEGER NOT NULL, fee INTEGER NOT NULL,
  dur INTEGER NOT NULL, entry REAL NOT NULL, start INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', result INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mk_demo(user_id INTEGER PRIMARY KEY, bal INTEGER NOT NULL);`);
function newMarket(name, v0, on) {
  return { name, CEN: v0, IDL: 0, TREND: 0, TON: false, TD: 1, TK: 0, AI: true, FROZEN: false, OPEN: on, started: on, XS: 'idle', XR: null, XOFF: 0, XA: 0, RS: 0, RN: 0, WH: 0, WL: 0, V: v0, ADM: 0,
    a: [], H: [], L: [], TB: 0, cnt: new Map() };
}
const MK = { demo: newMarket('demo', SBASE, true), live: newMarket('live', 0, false) }; // the live coin stays closed until the admin starts it
const SIM = MK.demo; // the older /game/market and /game/sim-adm routes follow the demo market
const mkName = (m) => (m === 'real' || m === 'live') ? 'live' : 'demo';
const simN = (S) => S.TB + S.a.length;
function simPush(S, v, hi, lo) { S.a.push(v); S.H.push(Math.max(v, hi == null ? v : hi)); S.L.push(Math.min(v, lo == null ? v : lo));
  if (S.a.length > 10080) { S.a.splice(0, 2520); S.H.splice(0, 2520); S.L.splice(0, 2520); S.TB += 2520; } }
// Open Buys and Sells for a market (real client trades, plus the older cnt reports for the demo market).
function simCounts(S) {
  const r = db.prepare("SELECT COALESCE(SUM(CASE WHEN dir>0 THEN 1 END),0) AS b, COALESCE(SUM(CASE WHEN dir<0 THEN 1 END),0) AS s FROM mk_trades WHERE status='open' AND mkt=?").get(S.name);
  let b = r.b, s = r.s; const now = Date.now();
  for (const [k, v] of S.cnt) { if (now - v.t > 6000) S.cnt.delete(k); else { b += v.b; s += v.s; } }
  return { b, s };
}
function simEndTrend(S) { S.CEN += S.TREND; S.TREND = 0; S.TON = false; }
function simStartTrend(S, d) { if (S.TON) S.CEN += S.TREND; S.TREND = 0; S.TON = true; S.TD = d; S.TK = 0; }
// AI: more Sells than Buys -> uptrend, more Buys than Sells -> downtrend, equal -> surplus on. Clients are told when the AI is on.
function simAi(S) { const { b, s } = simCounts(S), want = s > b ? 1 : b > s ? -1 : 0; if (want === 0) { if (S.TON) simEndTrend(S); } else if (!S.TON || S.TD !== want) simStartTrend(S, want); }
const simSync = (S) => { S.V = Math.max(0, S.CEN + S.IDL + S.TREND + S.XOFF); };
function simTick(S) {
  const mag = () => .01 + Math.random() * .49;
  if (!S.started) { /* closed market: flat */ }
  else if (S.FROZEN) {
    if (S.XR) { S.XR.k++; const k = S.XR.k, A = S.XA, W = Math.max(.02, A * .04), r = () => .3 + Math.random() * .7; let off;
      if (k <= 3) { off = (Math.random() - .5) * W * .6; S.WH = W * r(); S.WL = W * r(); }
      else if (k <= 7) { off = 3 * A * (k - 3) / 4; S.WH = W * r(); S.WL = W * r(); }
      else if (k <= 15) { off = 3 * A - 2 * A * (k - 7) / 8; S.WH = W * r(); S.WL = W * r(); }
      else off = A;
      S.XOFF = off; if (k >= XN) { S.CEN += S.XA; S.XOFF = 0; S.XR = null; S.FROZEN = false; S.OPEN = true; S.XS = 'idle'; } }
  } else {
    if (S.AI) simAi(S);
    if (S.TON) { S.TK++; S.TREND = S.TD * TSC * (SEQ[Math.min(S.TK, SN - 1)] - 1); if (S.TK >= SN - 1) { simEndTrend(S); if (S.AI) simAi(S); } }
    else { let sg = Math.random() < .5 ? 1 : -1; if (sg === S.RS && S.RN >= 5) sg = -sg; let st = sg * mag();
      if ((S.IDL + st > SBAND || S.IDL + st < -SBAND) && !(-sg === S.RS && S.RN >= 5)) { sg = -sg; st = sg * mag(); }
      if (S.IDL + st > SBAND) st = SBAND - S.IDL; else if (S.IDL + st < -SBAND) st = -SBAND - S.IDL;
      S.RN = sg === S.RS ? S.RN + 1 : 1; S.RS = sg; S.IDL += st; }
  }
  simSync(S); const pv = S.a.length ? S.a[S.a.length - 1] : S.V; simPush(S, S.V, Math.max(pv, S.V) + S.WH, Math.min(pv, S.V) - S.WL); S.WH = S.WL = 0;
}
// Wallets: live = the user's real wallet (cents), demo = a practice wallet that starts at $10.
function demoBal(uid) { const r = db.prepare('SELECT bal FROM mk_demo WHERE user_id=?').get(uid); if (r) return r.bal; db.prepare('INSERT INTO mk_demo(user_id,bal) VALUES(?,?)').run(uid, MK_DEMO0); return MK_DEMO0; }
const demoAdd = (uid, d) => { const b = demoBal(uid) + d; if (b < 0) throw new Error('Insufficient funds'); db.prepare('UPDATE mk_demo SET bal=? WHERE user_id=?').run(b, uid); };
const mkBal = (uid, m) => m === 'live' ? db.prepare('SELECT balance FROM users WHERE id=?').get(uid).balance : demoBal(uid);
// Close one trade. force = a fixed profit/loss in cents (used to void trades). Returns the profit/loss in cents, or null if it was already closed.
function mkSettle(t, force) {
  return db.transaction(() => {
    const cur = db.prepare('SELECT status FROM mk_trades WHERE id=?').get(t.id); if (!cur || cur.status !== 'open') return null;
    const S = MK[t.mkt], bal = mkBal(t.user_id, t.mkt);
    let p;
    if (force != null) p = force;
    else { const el = Math.min(1, (Date.now() - t.start) / 1000 / t.dur), m = SEQ[Math.min(SN - 1, Math.floor(el * SN))], v = Math.round(t.stake * m);
      p = t.dir * (S.V - t.entry) >= 0 ? v : -Math.min(v, t.stake + bal); }
    const net = t.stake + p; // what comes back to the wallet (negative = a further deduction, never more than the balance)
    if (net !== 0) {
      if (t.mkt === 'live') {
        const T = TID(), tx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'chart_close',?,'success',?)").run(t.user_id, Math.abs(net), 'CHART-' + t.id).lastInsertRowid;
        if (net > 0) {
          const short = net - treasuryBal();
          if (short > 0) { const ctx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'house_cover',?,'success',?)").run(T, short, 'CHART-COVER-' + t.id).lastInsertRowid; post(T, ctx, 'credit', short); }
          post(T, tx, 'house_out', -net); post(t.user_id, tx, 'credit', net);
        } else { post(t.user_id, tx, 'debit', net); post(T, tx, 'house_in', -net); }
      } else demoAdd(t.user_id, net);
    }
    S.ADM -= p / 100;
    db.prepare("UPDATE mk_trades SET status='closed', result=? WHERE id=?").run(p, t.id);
    return p;
  })();
}
function mkExpire(S) {
  for (const t of db.prepare("SELECT * FROM mk_trades WHERE status='open' AND mkt=? AND start+dur*1000<=?").all(S.name, Date.now())) {
    try { mkSettle(t); } catch (e) { console.error('mk settle', t.id, e.message); }
  }
}
// Prices live only in memory, so trades left open by a restart are voided: the stake comes back, the commission is kept.
for (const t of db.prepare("SELECT * FROM mk_trades WHERE status='open'").all()) { try { mkSettle(t, 0); } catch (e) { console.error('mk void', t.id, e.message); } }
for (const S of Object.values(MK)) for (let i = 0; i < 1500; i++) simTick(S);
setInterval(() => { for (const S of Object.values(MK)) { try { simTick(S); mkExpire(S); } catch (e) { console.error('sim', S.name, e.message); } } }, 1000);
function simView(S, withHist) {
  const n = simN(S), L = S.a.length, k = Math.min(5, L);
  const o = { n, v: S.V, hi: S.H[L - 1], lo: S.L[L - 1], sp: S.IDL, ton: S.TON, fr: S.FROZEN, op: S.OPEN, xs: S.XS, xa: S.XA, xk: S.XR ? S.XR.k : 0, ai: S.AI,
    tv: S.a.slice(-k), th: S.H.slice(-k), tl: S.L.slice(-k), de: true, dv: 1, sb: 10, now: Date.now() };
  if (withHist) { const st = Math.floor(Math.max(0, L - 3000) / 2520) * 2520; o.hist = { a: S.a.slice(st), H: S.H.slice(st), L: S.L.slice(st), TB: S.TB + st }; }
  return o;
}
function mkView(uid, m) {
  const rows = db.prepare(`SELECT * FROM (SELECT * FROM mk_trades WHERE user_id=? AND mkt=? AND status='open'
    UNION ALL SELECT * FROM (SELECT * FROM mk_trades WHERE user_id=? AND mkt=? AND status<>'open' ORDER BY id DESC LIMIT 10)) ORDER BY id DESC`).all(uid, m, uid, m);
  return { now: Date.now(), bal: mkBal(uid, m) / 100, trades: rows.map(t => ({ id: t.id, status: t.status, dir: t.dir, stake: t.stake / 100, fee: t.fee / 100, dur: t.dur, entry: t.entry, start: t.start, result: t.result / 100 })) };
}
// Client routes (index page). m is 'demo' or 'real'.
app.get('/mk/feed', auth, wrap(async (req, res) => {
  const S = MK[mkName(req.query.m)], since = Number(req.query.since), n = simN(S), L = S.a.length;
  const o = { n, st: { v: S.V, ton: S.TON, fr: S.FROZEN, op: S.OPEN, xs: S.XS, ai: S.AI, ...simCounts(S) } };
  if (!(since >= S.TB) || since > n || n - since > L) { const st = Math.floor(Math.max(0, L - 3000) / 2520) * 2520; o.full = true; o.a = S.a.slice(st); o.H = S.H.slice(st); o.L = S.L.slice(st); o.TB = S.TB + st; }
  else { const k = n - since; o.a = S.a.slice(L - k); o.H = S.H.slice(L - k); o.L = S.L.slice(L - k); }
  res.json(o);
}));
app.get('/mk/me', auth, wrap(async (req, res) => { res.json(mkView(req.uid, mkName(req.query.m))); }));
app.post('/mk/trade', auth, wrap(async (req, res) => {
  if (req.role === 'treasury') throw new Error('The Treasury account cannot play');
  const m = mkName(req.body.m), S = MK[m];
  if (!S.started || !S.OPEN) throw new Error('Trading is closed right now.');
  const dir = req.body.dir === 'buy' ? 1 : req.body.dir === 'sell' ? -1 : 0; if (!dir) throw new Error('Choose Buy or Sell');
  const dur = Number(req.body.dur); if (!Number.isInteger(dur) || dur < 10 || dur > 90) throw new Error('Choose a close time from 10 to 90 seconds');
  const stake = cents(req.body.stake, MK_MIN, MK_MAX), fee = Math.round(stake * MK_FEE);
  db.transaction(() => {
    if (db.prepare("SELECT COUNT(*) AS c FROM mk_trades WHERE user_id=? AND mkt=? AND status='open'").get(req.uid, m).c >= MK_OPEN_MAX) throw new Error('Too many open trades. Close one first.');
    if (stake + fee > mkBal(req.uid, m)) throw new Error('Not enough balance. A ' + Math.round(MK_FEE * 100) + '% commission is added to the stake.');
    if (m === 'live') {
      const tx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'chart_open',?,'success','CHART')").run(req.uid, stake + fee).lastInsertRowid;
      post(req.uid, tx, 'debit', -(stake + fee)); post(TID(), tx, 'house_in', stake + fee);
    } else demoAdd(req.uid, -(stake + fee));
    S.ADM += fee / 100;
    db.prepare('INSERT INTO mk_trades(user_id,mkt,dir,stake,fee,dur,entry,start) VALUES(?,?,?,?,?,?,?,?)').run(req.uid, m, dir, stake, fee, dur, S.V, Date.now());
  })();
  res.json(mkView(req.uid, m));
}));
app.post('/mk/close', auth, wrap(async (req, res) => {
  const t = db.prepare('SELECT * FROM mk_trades WHERE id=? AND user_id=?').get(Number(req.body.id), req.uid);
  if (!t) throw new Error('Trade not found');
  if (mkSettle(t) === null) throw new Error('Trade already closed.');
  res.json(mkView(req.uid, t.mkt));
}));
// Older client routes (demo market only).
app.get('/game/market', auth, wrap(async (req, res) => {
  const b = Number(req.query.b), s = Number(req.query.s);
  if (Number.isFinite(b) && Number.isFinite(s) && b >= 0 && s >= 0 && b < 1000 && s < 1000) SIM.cnt.set(req.uid, { b, s, t: Date.now() });
  res.json(simView(SIM, req.query.hist === '1'));
}));
app.post('/game/sim-adm', auth, wrap(async (req, res) => { const d = Number(req.body.d); if (Number.isFinite(d) && Math.abs(d) <= 1000) SIM.ADM += d; res.json({ ok: true }); }));
// Admin routes: m = 'demo' or 'live'.
const adminSim = (S, hist) => ({ ...simView(S, hist), adm: S.ADM, counts: simCounts(S),
  marks: db.prepare('SELECT start AS t, entry AS p, dir, stake/100.0 AS stake FROM mk_trades WHERE mkt=? ORDER BY id DESC LIMIT 200').all(S.name).reverse() });
app.get('/admin/sim', auth, adminOnly, wrap(async (req, res) => { res.json(adminSim(MK[mkName(req.query.m)], req.query.hist === '1')); }));
app.post('/admin/sim', auth, adminOnly, wrap(async (req, res) => {
  const b = req.body || {}, S = MK[mkName(b.m)]; let note = '';
  if (b.action === 'mode') { if (S.started && !S.FROZEN) { S.AI = false; if (b.val === 'auto') { if (S.TON) simEndTrend(S); } else if (b.val === 'up' || b.val === 'down') simStartTrend(S, b.val === 'up' ? 1 : -1); else throw new Error('Unknown mode'); } note = 'mode ' + b.val; }
  else if (b.action === 'ai') { if (S.started && !S.FROZEN) { S.AI = !!b.on; if (S.AI) simAi(S); else if (S.TON) simEndTrend(S); } note = 'ai ' + (b.on ? 'on' : 'off'); }
  else if (b.action === 'xfer-close') { const a = Number(b.amount); if (!(a > 0 && a <= 100000)) throw new Error('Enter an amount above 0');
    if (S.XS !== 'idle') throw new Error('A transfer is already in progress');
    if (b.src === 'transfer') { if (a > S.ADM + 1e-9) throw new Error('Admin transfer holds only $' + Math.max(0, S.ADM).toFixed(2)); S.ADM -= a; }
    for (const t of db.prepare("SELECT * FROM mk_trades WHERE status='open' AND mkt=?").all(S.name)) mkSettle(t); // open trades close at the current value
    if (S.TON) simEndTrend(S); S.started = true; S.OPEN = false; S.FROZEN = true; S.XS = 'frozen'; S.XA = a; S.XR = null; S.XOFF = 0;
    note = 'close market, add $' + a.toFixed(2) + ' (' + (b.src === 'transfer' ? 'from admin transfer' : 'directly') + ')'; }
  else if (b.action === 'xfer-start') { if (S.XS !== 'frozen') throw new Error('Close the market first'); S.XS = 'running'; S.XR = { k: 0 }; note = 'start transfer'; }
  else if (b.action === 'open') { if (S.XS !== 'idle') throw new Error('A transfer is in progress'); if (!S.started) throw new Error('Start the market with a transfer first'); S.OPEN = true; note = 'open trading'; }
  else throw new Error('Unknown action');
  audit(req.uid, 'sim_market', 0, S.name + ': ' + note);
  simSync(S); res.json(adminSim(S, false));
}));

// Treasury (admin): shows the house account and lets the admin move money to clients.
app.get('/admin/treasury', auth, adminOnly, wrap(async (req, res) => {
  const g = db.prepare("SELECT COALESCE(SUM(fee),0) AS fees, COALESCE(SUM(CASE WHEN status='open' THEN (stake-fee)*"+G.mult+" END),0) AS exposure, COUNT(CASE WHEN status='open' THEN 1 END) AS open FROM game_bets").get();
  const log = db.prepare('SELECT entry,delta,balance_after,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 20').all(TID());
  res.json({ covered: db.prepare("SELECT COALESCE(SUM(amount),0) AS c FROM txs WHERE kind='house_cover'").get().c, balance: treasuryBal(), fees: g.fees, exposure: g.exposure, open: g.open, win_chance_pct: Math.round(winChance() * 100), target: G.target, chance_low_pct: Math.round(G.lo * 100), chance_high_pct: Math.round(G.hi * 100), log });
}));
app.post('/admin/treasury/send', auth, adminOnly, wrap(async (req, res) => { // same as a transfer from 'treasury'
  const amount = cents(req.body.amount, 0.01, Number(E.TRANSFER_MAX_USD || 1000)), to = normPhone(req.body.to), note = String(req.body.note || '').trim().slice(0, 100);
  if (!note) throw new Error('A reason is required');
  const b = db.prepare('SELECT id, role, email FROM users WHERE phone=?').get(to);
  if (!b || b.role === 'treasury') throw new Error('No account with that phone number');
  db.transaction(() => {
    const t = TID();
    if (treasuryBal() - amount < openPayouts()) throw new Error('Not enough free funds: open game bets must stay covered');
    const out = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'treasury_out',?,'success',?)").run(t, amount, note).lastInsertRowid;
    const inn = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'transfer_in',?,'success',?)").run(b.id, amount, note).lastInsertRowid;
    post(t, out, 'debit', -amount); post(b.id, inn, 'credit', amount);
    audit(req.uid, 'treasury_send', b.id, `$${amount / 100} to ${b.email}: ${note}`);
  })();
  res.json({ ok: true });
}));
// Funding adds the business's own reserve so the game can pay winners. It must match money you really put in.
app.post('/admin/treasury/fund', auth, adminOnly, wrap(async (req, res) => {
  const amount = cents(req.body.amount, 1, Number(E.TREASURY_FUND_MAX_USD || 5000)), note = String(req.body.note || '').trim().slice(0, 100);
  if (!note) throw new Error('A reason is required (where the money came from)');
  db.transaction(() => {
    const t = TID();
    const tx = db.prepare("INSERT INTO txs(user_id,kind,amount,status,receipt) VALUES(?,'reserve_in',?,'success',?)").run(t, amount, note).lastInsertRowid;
    post(t, tx, 'credit', amount);
    audit(req.uid, 'treasury_fund', t, `$${amount / 100}: ${note}`);
  })();
  res.json({ ok: true });
}));

// ---- Daraja callbacks (always ACK with 200) ----
const cbIps = (E.CALLBACK_IPS || '').split(',').map(x => x.trim()).filter(Boolean); // optional: Safaricom's IPs
const guard = (req, res, next) => (sameSecret(req.params.secret, E.CALLBACK_SECRET) && (!cbIps.length || cbIps.includes(req.ip))) ? next() : res.sendStatus(404);
const ack = (res) => res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

app.post('/mpesa/stk-callback/:secret', guard, (req, res) => {
  try {
    console.log('stk-callback body', JSON.stringify(req.body).slice(0, 800));
    const c = (req.body.Body && req.body.Body.stkCallback) || req.body.stkCallback || req.body;
    const tx = db.prepare("SELECT * FROM txs WHERE checkout_id=? AND kind='topup'").get(c.CheckoutRequestID);
    if (tx && tx.status === 'pending') {
      db.transaction(() => {
        if (Number(c.ResultCode) === 0) {
          const items = c.CallbackMetadata.Item;
          const receipt = (items.find(i => i.Name === 'MpesaReceiptNumber') || {}).Value;
          const paid = (items.find(i => i.Name === 'Amount') || {}).Value;
          if (Number(paid) === tx.kes) {
            post(tx.user_id, tx.id, 'credit', tx.amount);
            db.prepare("UPDATE txs SET status='success', receipt=?, raw=? WHERE id=?").run(receipt, JSON.stringify(c), tx.id);
          } else db.prepare("UPDATE txs SET status='review', raw=? WHERE id=?").run(JSON.stringify(c), tx.id);
        } else db.prepare("UPDATE txs SET status='failed', raw=? WHERE id=?").run(JSON.stringify(c), tx.id);
      })();
    }
  } catch (e) { console.error('stk-callback', e.message); }
  ack(res);
});

app.post('/mpesa/b2c-result/:secret', guard, (req, res) => {
  try {
    const r = req.body.Result;
    const tx = db.prepare("SELECT * FROM txs WHERE conv_id=? AND kind='withdraw'").get(r.OriginatorConversationID);
    if (tx && tx.status === 'pending') {
      db.transaction(() => {
        if (r.ResultCode === 0) db.prepare("UPDATE txs SET status='success', receipt=?, raw=? WHERE id=?").run(r.TransactionID, JSON.stringify(r), tx.id);
        else { post(tx.user_id, tx.id, 'refund', tx.amount); db.prepare("UPDATE txs SET status='failed', raw=? WHERE id=?").run(JSON.stringify(r), tx.id); }
      })();
    }
  } catch (e) { console.error('b2c-result', e.message); }
  ack(res);
});

// Timeout = outcome unknown. Do NOT auto-refund; verify with Transaction Status or the M-Pesa statement.
app.post('/mpesa/b2c-timeout/:secret', guard, (req, res) => { console.warn('B2C timeout', JSON.stringify(req.body)); ack(res); });

app.listen(E.PORT || 3000, () => {
  console.log(`Wallet API on :${E.PORT || 3000} (${E.MPESA_ENV || 'sandbox'}), db: ${DB_FILE}`);
  console.log(BUNI
    ? `Mode: KCB Buni | gateway ${E.KCB_BASE_URL || 'https://uat.buni.kcbgroup.com'} | payouts ${E.KCB_PAYOUTS === '1' ? 'ON' : 'OFF'}`
    : `Mode: Daraja | ${BASE} | payouts ${(E.INITIATOR_NAME && E.SECURITY_CREDENTIAL) ? 'configured' : 'not configured'}`);
});
