# 🔐 Secure Login System

A command-line authentication system written in **pure Python (standard library only)** that demonstrates modern, industry-standard security practices. Built as a Cyber Security project.

## Features

| Feature | How it's done |
|---|---|
| Password hashing | `scrypt` (memory-hard) with a unique 16-byte random salt per user |
| Pepper (optional) | HMAC-SHA256 with a server secret from the `APP_PEPPER` env variable |
| Timing-attack protection | `hmac.compare_digest` for all secret comparisons |
| SQL injection protection | Parameterized queries only |
| Password policy | 12+ chars, upper/lower/digit/special, common-password blocklist, no username inside |
| Brute-force protection | Account lockout: 5 failed attempts → locked for 5 minutes |
| User enumeration protection | Generic error messages + dummy hash check to equalise response time |
| Two-factor authentication | TOTP (RFC 6238), works with Google Authenticator / Authy |
| Secure sessions | `secrets.token_urlsafe(32)`, only SHA-256 hash stored, 15-minute expiry |
| Audit logging | Every register/login/lockout/2FA/password event is logged |
| Safe input | Passwords typed via `getpass` (hidden) |

## Two versions

- `secure_login.py`: command-line app, **no dependencies**
- `app.py`: Flask **web app** (imports the security core from `secure_login.py`). Adds CSRF tokens, secure cookies, security headers (CSP, X-Frame-Options, HSTS), session-fixation protection and per-IP rate limiting.

## Requirements

- Python **3.8+**
- CLI version: nothing to install
- Web version: `pip install -r requirements.txt` (Flask, gunicorn)

## Run the web version

```bash
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000
```

Production (e.g. Render): start command `gunicorn app:app`, with environment variables
`SECRET_KEY` (long random string), `APP_PEPPER`, `COOKIE_SECURE=1`, `BEHIND_PROXY=1`.
Note: SQLite on free hosting tiers can be wiped on redeploy; use a persistent disk or a hosted database for real use.

## Run the command-line version

```bash
git clone https://github.com/<your-username>/secure-login-system.git
cd secure-login-system
python secure_login.py
```

Optional: set a pepper for extra protection.

```bash
# Linux / macOS
export APP_PEPPER="a-long-random-secret"
# Windows (PowerShell)
$env:APP_PEPPER="a-long-random-secret"
```

> Use the **same** pepper every run. If you change it, existing users can no longer log in.

## Usage

```
=== SECURE LOGIN SYSTEM ===
1) Register
2) Login
3) Exit
```

After login you can: enable 2FA, change password, view your security log, or log out.

## Project structure

```
secure-login-system/
├── secure_login.py      # security core + command-line app
├── app.py               # Flask web version
├── index.html           # GitHub Pages project page
├── requirements.txt     # Flask, gunicorn (web version only)
├── Procfile             # start command for hosting platforms
├── .gitignore
├── README.md            # this file
├── Project_Report.docx  # full project report
└── secure_login.db      # created automatically on first run (do not commit)
```

## Database schema

- **users**: id, username, password_hash, failed_attempts, locked_until, totp_secret, created_at
- **sessions**: token_hash, user_id, expires_at
- **audit_log**: id, ts, username, event

## Testing ideas

1. Register with a weak password → rejected with the reasons.
2. Enter a wrong password 5 times → account locks for 5 minutes.
3. Log in with an unknown user vs. a wrong password → identical error message.
4. Enable 2FA, then log in with a wrong code → rejected.
5. Open `secure_login.db` in a SQLite viewer → no plaintext passwords or session tokens.
6. Try `' OR '1'='1` as the username → login fails (SQL injection blocked).

## Limitations

- Command-line app; a web version would also need HTTPS, CSRF protection and secure cookies.
- TOTP secrets are stored unencrypted in the database (should be encrypted in production).
- Lockout is per account, not per IP address.

## Future improvements

Flask web interface, email password reset, backup codes for 2FA, encrypted TOTP secrets, CAPTCHA, IP-based rate limiting.

## Disclaimer

Created for educational purposes. Review and harden before using in production.

## License

MIT
