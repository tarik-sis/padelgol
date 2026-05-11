/*
 * PadelGol — Intentionally Vulnerable Demo App
 *
 * WARNING: This application is deliberately insecure. It is designed
 * exclusively for demonstrating a cybersecurity scanning/review product.
 * DO NOT deploy publicly. Run only on localhost or an isolated lab network.
 *
 * See README.md for the catalogue of planted vulnerabilities.
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const http = require('http');
const https = require('https');
const url = require('url');
const { db, init } = require('./db');

// VULN: hardcoded secret committed in source — Sensitive Data Exposure
const JWT_SECRET = 'padelgol-super-secret-2025';
const API_KEY = 'sk_live_padelgol_51XyZabcDEF1234567890';

const app = express();
const PORT = process.env.PORT || 3000;

init();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// VULN: permissive CORS with credentials — allows any origin to read responses
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  // VULN: missing security headers (no X-Frame-Options, no CSP, no HSTS, no X-Content-Type-Options)
  next();
});

// VULN: predictable, signed-with-weak-secret session id; cookie missing httpOnly/secure/sameSite
app.use(session({
  secret: 'padelgol-session-key',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false, sameSite: 'none' }
}));

// File upload — VULN: no MIME/extension whitelist, original filename trusted
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => cb(null, file.originalname)
  })
});
app.use('/uploads', express.static(uploadDir));

// Helpers — VULN: trust cookie role claim without verification on some routes
function currentUser(req) {
  if (req.session && req.session.user) return req.session.user;
  // VULN: also accept user identity from a plain cookie — trivial impersonation
  if (req.cookies && req.cookies.uid) {
    return { id: parseInt(req.cookies.uid, 10), username: req.cookies.uname || 'anon', role: req.cookies.role || 'user' };
  }
  return null;
}

function requireLogin(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.redirect('/login');
  req.user = u;
  next();
}

// ---------------- Routes ----------------

app.get('/', (req, res) => {
  db.all('SELECT * FROM courts LIMIT 6', (err, courts) => {
    res.render('index', { user: currentUser(req), courts: courts || [], q: null, results: null, error: null });
  });
});

// VULN: Reflected XSS — `q` is injected into template without escaping.
// VULN: SQL Injection — query interpolated into LIKE clause.
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT * FROM courts WHERE name LIKE '%${q}%' OR location LIKE '%${q}%' OR description LIKE '%${q}%'`;
  db.all(sql, (err, results) => {
    res.render('search', { user: currentUser(req), q, results: results || [], error: err ? err.message : null });
  });
});

// ---------------- Auth ----------------

app.get('/login', (req, res) => {
  res.render('login', { user: currentUser(req), error: req.query.error, next: req.query.next || '/' });
});

// VULN: SQL Injection in login (classic ' OR '1'='1)
// VULN: passwords compared in plaintext from DB
// VULN: open redirect via `next` parameter
app.post('/login', (req, res) => {
  const { username, password, next: nextUrl } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(sql, (err, row) => {
    if (err) return res.status(500).send('<pre>' + err.stack + '</pre>'); // VULN: verbose error
    if (!row) return res.redirect('/login?error=Invalid+credentials');
    req.session.user = { id: row.id, username: row.username, role: row.role };
    // VULN: also drop identity into plain cookies — readable by JS, no httpOnly
    res.cookie('uid', row.id);
    res.cookie('uname', row.username);
    res.cookie('role', row.role);
    // VULN: JWT signed with hardcoded secret + `alg:none` accepted later
    const token = jwt.sign({ sub: row.id, username: row.username, role: row.role }, JWT_SECRET);
    res.cookie('token', token);
    // VULN: open redirect — no host validation on `next`
    return res.redirect(nextUrl || '/');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('uid'); res.clearCookie('uname'); res.clearCookie('role'); res.clearCookie('token');
    res.redirect('/');
  });
});

app.get('/register', (req, res) => {
  res.render('register', { user: currentUser(req), error: null });
});

// VULN: Mass Assignment — `role` accepted from request body, so attacker registers as admin.
// VULN: no password strength check, plaintext storage
app.post('/register', (req, res) => {
  const { username, password, email, role, security_question, security_answer } = req.body;
  const r = role || 'user'; // mass-assignment sink
  db.run(
    'INSERT INTO users (username, password, email, role, security_question, security_answer) VALUES (?, ?, ?, ?, ?, ?)',
    [username, password, email, r, security_question, security_answer],
    function (err) {
      if (err) return res.render('register', { user: null, error: err.message }); // VULN: error leaks
      req.session.user = { id: this.lastID, username, role: r };
      res.redirect('/');
    }
  );
});

// VULN: password reset by security answer — answer compared case-sensitively, leaks question
//        and allows enumeration of users (different response when user not found).
app.get('/forgot', (req, res) => {
  res.render('forgot', { user: currentUser(req), step: 'username', data: {}, error: null });
});
app.post('/forgot', (req, res) => {
  const { username, answer, new_password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (!row) return res.render('forgot', { user: null, step: 'username', data: {}, error: 'No such user' });
    if (!answer) return res.render('forgot', { user: null, step: 'answer', data: { username, question: row.security_question }, error: null });
    if (answer.toLowerCase() === (row.security_answer || '').toLowerCase()) {
      if (new_password) {
        db.run('UPDATE users SET password = ? WHERE id = ?', [new_password, row.id], () => res.redirect('/login'));
      } else {
        res.render('forgot', { user: null, step: 'reset', data: { username }, error: null });
      }
    } else {
      res.render('forgot', { user: null, step: 'answer', data: { username, question: row.security_question }, error: 'Wrong answer' });
    }
  });
});

// ---------------- Courts & bookings ----------------

app.get('/courts', (req, res) => {
  // VULN: SQL injection via `sport` filter
  const sport = req.query.sport;
  let sql = 'SELECT * FROM courts';
  if (sport) sql += ` WHERE sport = '${sport}'`;
  db.all(sql, (err, courts) => {
    res.render('courts', { user: currentUser(req), courts: courts || [], sport, error: err ? err.message : null });
  });
});

// VULN: SQL Injection in `id` (numeric concat, no parameterization)
// VULN: Stored XSS — reviews rendered with raw HTML
app.get('/courts/:id', (req, res) => {
  const id = req.params.id;
  db.get(`SELECT * FROM courts WHERE id = ${id}`, (err, court) => {
    if (err) return res.status(500).send('<pre>' + err.stack + '</pre>');
    db.all(`SELECT * FROM reviews WHERE court_id = ${id} ORDER BY created_at DESC`, (err2, reviews) => {
      res.render('court', { user: currentUser(req), court, reviews: reviews || [] });
    });
  });
});

// VULN: Stored XSS — review content saved as-is and rendered unescaped
// VULN: no CSRF protection (no token, sameSite=none cookies)
app.post('/courts/:id/review', requireLogin, (req, res) => {
  const id = req.params.id;
  const { content } = req.body;
  db.run('INSERT INTO reviews (court_id, user_id, author, content) VALUES (?, ?, ?, ?)',
    [id, req.user.id, req.user.username, content],
    () => res.redirect('/courts/' + id));
});

// ---------------- Bookings ----------------

app.get('/book/:courtId', requireLogin, (req, res) => {
  db.get('SELECT * FROM courts WHERE id = ?', [req.params.courtId], (err, court) => {
    if (!court) return res.status(404).send('Court not found');
    res.render('book', { user: req.user, court, error: null });
  });
});

// VULN: Stored XSS — `notes` rendered unescaped on bookings page
// VULN: no CSRF token, accepts cross-origin POST due to permissive CORS
app.post('/book/:courtId', requireLogin, (req, res) => {
  const { slot_date, slot_time, notes } = req.body;
  db.run('INSERT INTO bookings (user_id, court_id, slot_date, slot_time, notes) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, req.params.courtId, slot_date, slot_time, notes],
    () => res.redirect('/my-bookings'));
});

app.get('/my-bookings', requireLogin, (req, res) => {
  db.all(`SELECT b.*, c.name AS court_name FROM bookings b JOIN courts c ON c.id = b.court_id WHERE b.user_id = ${req.user.id}`,
    (err, rows) => {
      res.render('my-bookings', { user: req.user, bookings: rows || [] });
    });
});

// VULN: IDOR — any logged-in user can read/cancel any booking by id
app.get('/booking/:id', requireLogin, (req, res) => {
  db.get(`SELECT b.*, c.name AS court_name, u.username AS owner FROM bookings b
          JOIN courts c ON c.id = b.court_id
          JOIN users u ON u.id = b.user_id
          WHERE b.id = ${req.params.id}`, (err, row) => {
    if (!row) return res.status(404).send('Not found');
    res.render('booking', { user: req.user, booking: row });
  });
});

app.post('/booking/:id/cancel', requireLogin, (req, res) => {
  // VULN: IDOR — no ownership check
  db.run('DELETE FROM bookings WHERE id = ?', [req.params.id], () => res.redirect('/my-bookings'));
});

// ---------------- Profile ----------------

app.get('/profile', requireLogin, (req, res) => {
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, u) => {
    res.render('profile', { user: req.user, profile: u });
  });
});

// VULN: Stored XSS — bio rendered as raw HTML in profile view
// VULN: Mass Assignment — Object.assign of req.body lets attacker set role/credit_card
//        and even prototype properties (prototype pollution sink).
app.post('/profile', requireLogin, (req, res) => {
  const payload = Object.assign({}, req.body);
  const fields = Object.keys(payload).filter(k => ['username','email','bio','role','credit_card','password'].includes(k));
  if (fields.length === 0) return res.redirect('/profile');
  const set = fields.map(f => `${f} = ?`).join(', ');
  const vals = fields.map(f => payload[f]);
  vals.push(req.user.id);
  db.run(`UPDATE users SET ${set} WHERE id = ${req.user.id}`, vals.slice(0, -1), () => res.redirect('/profile'));
});

// VULN: Unrestricted file upload — any extension/MIME, served back from /uploads
//        Combined with the static serve, an uploaded .html executes scripts in same origin.
app.post('/profile/avatar', requireLogin, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.redirect('/profile');
  const avatarUrl = '/uploads/' + req.file.filename;
  db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatarUrl, req.user.id], () => res.redirect('/profile'));
});

// ---------------- Messages ----------------

// VULN: IDOR + missing authorization — anyone can read anyone's messages by query param
app.get('/messages', requireLogin, (req, res) => {
  const who = req.query.user || req.user.username;
  db.all(`SELECT * FROM messages WHERE to_user = '${who}' ORDER BY created_at DESC`, (err, rows) => {
    res.render('messages', { user: req.user, who, messages: rows || [], error: err ? err.message : null });
  });
});

// ---------------- Admin ----------------

// VULN: Missing authorization — /admin only checks login, not role
// (admin link is hidden in UI but route is reachable directly)
app.get('/admin', requireLogin, (req, res) => {
  db.all('SELECT id, username, email, role, credit_card FROM users', (err, users) => {
    db.all('SELECT * FROM bookings', (err2, bookings) => {
      res.render('admin', { user: req.user, users: users || [], bookings: bookings || [], result: null });
    });
  });
});

// VULN: Command Injection — `host` passed straight to shell
app.get('/admin/ping', requireLogin, (req, res) => {
  const host = req.query.host || '127.0.0.1';
  exec('ping -c 1 ' + host, (err, stdout, stderr) => {
    res.render('admin-result', { user: req.user, title: 'Ping', output: (stdout || '') + (stderr || '') + (err ? err.message : '') });
  });
});

// VULN: SSRF — fetches any URL the server can reach (including localhost/metadata)
app.get('/admin/fetch', requireLogin, (req, res) => {
  const target = req.query.url;
  if (!target) return res.send('Provide ?url=');
  const lib = target.startsWith('https') ? https : http;
  lib.get(target, r => {
    let data = '';
    r.on('data', c => data += c);
    r.on('end', () => res.render('admin-result', { user: req.user, title: 'Fetch ' + target, output: data.slice(0, 20000) }));
  }).on('error', e => res.render('admin-result', { user: req.user, title: 'Fetch error', output: e.message }));
});

// VULN: Path Traversal / LFI — `file` joined into log dir without sanitization
app.get('/admin/logs', requireLogin, (req, res) => {
  const file = req.query.file || 'access.log';
  const full = path.join(__dirname, 'logs', file);
  fs.readFile(full, 'utf8', (err, data) => {
    res.render('admin-result', { user: req.user, title: 'Log: ' + file, output: err ? err.message : data });
  });
});

// VULN: Arbitrary file download via path traversal
app.get('/download', (req, res) => {
  const f = req.query.file;
  if (!f) return res.send('Provide ?file=');
  const full = path.resolve(__dirname, f); // no jail check
  fs.readFile(full, (err, data) => {
    if (err) return res.status(500).send('<pre>' + err.message + '</pre>');
    res.setHeader('Content-Type', 'text/plain');
    res.send(data);
  });
});

// VULN: Insecure deserialization via eval — accepts JS expression from query
app.get('/admin/calc', requireLogin, (req, res) => {
  const expr = req.query.expr || '1+1';
  let out;
  try { out = String(eval(expr)); } catch (e) { out = e.message; } // eslint-disable-line no-eval
  res.render('admin-result', { user: req.user, title: 'Calc', output: out });
});

// VULN: Debug endpoint leaks env vars, secrets, source paths
app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    secrets: { JWT_SECRET, API_KEY },
    cwd: process.cwd(),
    versions: process.versions,
    argv: process.argv,
    session: req.session,
    cookies: req.cookies
  });
});

// VULN: JWT verification accepts `alg:none` — forged tokens are honored
app.get('/api/whoami', (req, res) => {
  const token = req.cookies.token || (req.headers.authorization || '').replace(/^Bearer\s+/, '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    const parts = token.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    let payload;
    if (header.alg === 'none') {
      payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    } else {
      payload = jwt.verify(token, JWT_SECRET);
    }
    res.json({ ok: true, payload });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// VULN: Open redirect (also used by login). Phishing-friendly.
app.get('/redirect', (req, res) => {
  const u = req.query.url || '/';
  res.redirect(u);
});

// VULN: Verbose error handler — full stack to client
app.use((err, req, res, next) => {
  res.status(500).send('<h1>Internal error</h1><pre>' + (err.stack || err.message) + '</pre>');
});

app.listen(PORT, () => {
  console.log(`PadelGol (VULNERABLE DEMO) running at http://localhost:${PORT}`);
  console.log('WARNING: This app is intentionally insecure. Do not expose to the internet.');
});
