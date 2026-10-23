#!/usr/bin/env python3
"""
Secure Login System - Web version (Flask)

Reuses the security core from secure_login.py (scrypt hashing, TOTP, lockout,
hashed session tokens, audit log) and adds web protections:
  - CSRF tokens on every POST form
  - HttpOnly + SameSite (+ Secure in production) cookies
  - Security headers (CSP, X-Frame-Options, nosniff, no-store, HSTS)
  - Session-fixation protection (session cleared at login)
  - Per-IP rate limiting on login/register
  - Autoescaped templates (XSS protection)

Run locally:   python app.py          ->  http://127.0.0.1:5000
Production:    gunicorn app:app
Env vars:      SECRET_KEY (required in production), APP_PEPPER, COOKIE_SECURE=1,
               BEHIND_PROXY=1 (on Render/Heroku etc.)
"""

import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from jinja2 import DictLoader

import secure_login as sl

app = Flask(__name__)
if os.environ.get("BEHIND_PROXY") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

if not os.environ.get("SECRET_KEY"):
    print("[!] SECRET_KEY not set - using a temporary random key (sessions reset on restart).")

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=sl.SESSION_TTL_SECONDS,
    MAX_CONTENT_LENGTH=16 * 1024,
)

# ----------------------------------------------------------------- TEMPLATES
BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}Secure Login{% endblock %}</title>
<style>
:root{--bg:#f4f6fb;--card:#fff;--text:#1b2433;--muted:#5b6678;--accent:#2f5bea;--border:#d9dfeb;--err:#c62828;--ok:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#0f1420;--card:#192030;--text:#e8ecf5;--muted:#9aa6bd;--accent:#6d8cff;--border:#2b3550;--err:#ef5350;--ok:#66bb6a}}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--text)}
nav{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--border)}
nav b{font-size:18px}nav a,nav button{color:var(--accent);text-decoration:none;background:none;border:0;font:inherit;cursor:pointer;margin-left:14px}
main{max-width:460px;margin:28px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px;margin-bottom:18px}
h1,h2{margin-top:0}label{display:block;margin:12px 0 4px;font-size:14px;color:var(--muted)}
input{width:100%;padding:11px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);font-size:16px}
.btn{margin-top:16px;width:100%;padding:12px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:16px;cursor:pointer}
.msg{padding:10px 12px;border-radius:8px;margin-bottom:12px;border:1px solid var(--border)}
.msg.error{color:var(--err)}.msg.success{color:var(--ok)}
code{word-break:break-all;background:var(--bg);padding:2px 6px;border-radius:4px}
table{width:100%;border-collapse:collapse;font-size:14px}td{padding:6px 4px;border-bottom:1px solid var(--border)}
small,.muted{color:var(--muted)}
</style></head><body>
<nav><b>&#128274; Secure Login</b><span>
{% if user %}<a href="{{ url_for('dashboard') }}">Dashboard</a>
<form method="post" action="{{ url_for('logout') }}" style="display:inline">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button>Logout</button></form>
{% else %}<a href="{{ url_for('login') }}">Login</a><a href="{{ url_for('register') }}">Register</a>{% endif %}
</span></nav>
<main>
{% for cat, m in get_flashed_messages(with_categories=true) %}<div class="msg {{ cat }}">{{ m }}</div>{% endfor %}
{% block content %}{% endblock %}
</main></body></html>"""

FORM_FIELDS = """<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">"""

TEMPLATES = {
    "base.html": BASE,
    "home.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h1>Secure Login System</h1>
<p class="muted">scrypt hashing, account lockout, TOTP two-factor authentication, CSRF protection and audit logging.</p>
<a class="btn" style="display:block;text-align:center;text-decoration:none" href="{{ url_for('login') }}">Login</a>
<a class="btn" style="display:block;text-align:center;text-decoration:none;background:transparent;color:var(--accent);border:1px solid var(--accent)" href="{{ url_for('register') }}">Create account</a></div>
{% endblock %}""",
    "login.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h2>Login</h2><form method="post" autocomplete="off">""" + FORM_FIELDS + """
<label>Username</label><input name="username" required maxlength="20" autofocus>
<label>Password</label><input name="password" type="password" required maxlength="128">
<button class="btn">Login</button></form></div>{% endblock %}""",
    "register.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h2>Create account</h2><form method="post" autocomplete="off">""" + FORM_FIELDS + """
<label>Username (3-20 letters, digits, _)</label><input name="username" required maxlength="20">
<label>Password</label><input name="password" type="password" required maxlength="128">
<label>Confirm password</label><input name="confirm" type="password" required maxlength="128">
<small>12+ characters with upper, lower, digit and special character.</small>
<button class="btn">Register</button></form></div>{% endblock %}""",
    "twofa.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h2>Two-factor authentication</h2><form method="post" autocomplete="off">""" + FORM_FIELDS + """
<label>6-digit code from your authenticator app</label>
<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus>
<button class="btn">Verify</button></form></div>{% endblock %}""",
    "dashboard.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h2>Welcome, {{ user.username }}</h2>
<p>Two-factor authentication: <b>{{ 'ON' if user.has_2fa else 'OFF' }}</b></p>
{% if not user.has_2fa %}<a href="{{ url_for('enable_2fa') }}">Enable 2FA</a> &middot; {% endif %}
<a href="{{ url_for('change_password') }}">Change password</a></div>
<div class="card"><h2>Recent security events</h2><table>
{% for ts, ev in events %}<tr><td>{{ ts }}</td><td>{{ ev }}</td></tr>{% endfor %}</table></div>
{% endblock %}""",
    "enable2fa.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h2>Enable 2FA</h2>
<p>In Google Authenticator / Authy choose <b>Enter a setup key</b> (time-based) and enter:</p>
<p><code>{{ secret }}</code></p><p class="muted">Or use this URI: <code>{{ uri }}</code></p>
<form method="post" autocomplete="off">""" + FORM_FIELDS + """
<label>Enter the 6-digit code to confirm</label>
<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>
<button class="btn">Confirm</button></form></div>{% endblock %}""",
    "change_password.html": """{% extends 'base.html' %}{% block content %}
<div class="card"><h2>Change password</h2><form method="post" autocomplete="off">""" + FORM_FIELDS + """
<label>Current password</label><input name="current" type="password" required maxlength="128">
<label>New password</label><input name="new" type="password" required maxlength="128">
<label>Confirm new password</label><input name="confirm" type="password" required maxlength="128">
<button class="btn">Change password</button></form></div>{% endblock %}""",
}
app.jinja_loader = DictLoader(TEMPLATES)


# ------------------------------------------------------------------ HELPERS
def db():
    if "db" not in g:
        g.db = sl.get_db()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        expected = session.get("csrf")
        sent = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            abort(400, "Invalid CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# Simple in-memory per-IP rate limiter (use Redis for multi-server setups)
_hits = defaultdict(deque)


def rate_limited(limit=15, window=60):
    now, q = time.time(), _hits[request.remote_addr]
    while q and q[0] < now - window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def current_user():
    token = session.get("token")
    if not token:
        return None
    uid = sl.validate_session(db(), token)
    if uid is None:
        session.clear()
        return None
    row = db().execute("SELECT id, username, totp_secret IS NOT NULL FROM users WHERE id = ?",
                       (uid,)).fetchone()
    return {"id": row[0], "username": row[1], "has_2fa": bool(row[2])} if row else None


@app.context_processor
def inject_user():
    return {"user": current_user()}


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = current_user()
        if user is None:
            flash("Please log in.", "error")
            return redirect(url_for("login"))
        g.user = user
        return fn(*a, **kw)
    return wrapper


def record_failure(d, uid, username, event):
    failed = d.execute("SELECT failed_attempts FROM users WHERE id = ?", (uid,)).fetchone()[0] + 1
    if failed >= sl.MAX_FAILED_ATTEMPTS:
        d.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                  (time.time() + sl.LOCKOUT_SECONDS, uid))
        sl.audit(d, username, "ACCOUNT_LOCKED")
    else:
        d.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, uid))
        sl.audit(d, username, event)
    d.commit()


def finish_login(d, uid, username):
    d.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (uid,))
    d.commit()
    session.clear()                                  # prevents session fixation
    session["token"] = sl.create_session(d, uid)
    session.permanent = True
    sl.audit(d, username, "LOGIN_SUCCESS")
    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------- ROUTES
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if rate_limited():
            flash("Too many requests. Slow down.", "error")
            return render_template("register.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not sl.USERNAME_RE.match(username):
            flash("Invalid username format.", "error")
        elif sl.validate_password(password, username):
            flash("Password must have: " + ", ".join(sl.validate_password(password, username)), "error")
        elif not hmac.compare_digest(password.encode(), request.form.get("confirm", "").encode()):
            flash("Passwords do not match.", "error")
        else:
            try:
                db().execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                             (username, sl.hash_password(password), time.time()))
                db().commit()
                sl.audit(db(), username, "REGISTER_SUCCESS")
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            except sl.sqlite3.IntegrityError:
                flash("Registration failed. Try a different username.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if rate_limited():
            flash("Too many attempts. Wait a minute.", "error")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()[:20]
        password = request.form.get("password", "")[:128]
        d = db()
        row = d.execute("SELECT id, password_hash, locked_until, totp_secret FROM users "
                        "WHERE username = ?", (username,)).fetchone()
        if row is None:
            sl.verify_password(password, sl.DUMMY_HASH)          # equalise timing
            sl.audit(d, username, "LOGIN_FAIL_UNKNOWN_USER")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        uid, pw_hash, locked_until, totp_secret = row
        if locked_until > time.time():
            sl.audit(d, username, "LOGIN_BLOCKED_LOCKED")
            flash(f"Account temporarily locked. Try again in {int(locked_until - time.time())} seconds.", "error")
            return render_template("login.html")
        if not sl.verify_password(password, pw_hash):
            record_failure(d, uid, username, "LOGIN_FAIL_BAD_PASSWORD")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if totp_secret:
            session.clear()
            session.update(pending_uid=uid, pending_user=username, pending_until=time.time() + 300)
            return redirect(url_for("twofa"))
        return finish_login(d, uid, username)
    return render_template("login.html")


@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    uid, username = session.get("pending_uid"), session.get("pending_user")
    if not uid or session.get("pending_until", 0) < time.time():
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        d = db()
        row = d.execute("SELECT totp_secret, locked_until FROM users WHERE id = ?", (uid,)).fetchone()
        if row[1] > time.time():
            flash("Account temporarily locked.", "error")
            return render_template("twofa.html")
        if sl.verify_totp(row[0], request.form.get("code", "")):
            return finish_login(d, uid, username)
        record_failure(d, uid, username, "LOGIN_FAIL_BAD_2FA")
        flash("Invalid 2FA code.", "error")
    return render_template("twofa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    events = db().execute("SELECT ts, event FROM audit_log WHERE username = ? "
                          "ORDER BY id DESC LIMIT 10", (g.user["username"],)).fetchall()
    return render_template("dashboard.html", events=events)


@app.route("/enable-2fa", methods=["GET", "POST"])
@login_required
def enable_2fa():
    if request.method == "POST":
        secret = session.get("setup_secret", "")
        if secret and sl.verify_totp(secret, request.form.get("code", "")):
            db().execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, g.user["id"]))
            db().commit()
            session.pop("setup_secret", None)
            sl.audit(db(), g.user["username"], "2FA_ENABLED")
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect code. Try again.", "error")
    secret = session.setdefault("setup_secret", sl.new_totp_secret())
    uri = f"otpauth://totp/SecureLogin:{g.user['username']}?secret={secret}&issuer=SecureLogin"
    return render_template("enable2fa.html", secret=secret, uri=uri)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        d, username = db(), g.user["username"]
        stored = d.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()[0]
        new = request.form.get("new", "")
        if not sl.verify_password(request.form.get("current", ""), stored):
            sl.audit(d, username, "PASSWORD_CHANGE_FAIL")
            flash("Current password is incorrect.", "error")
        elif sl.validate_password(new, username):
            flash("Password must have: " + ", ".join(sl.validate_password(new, username)), "error")
        elif not hmac.compare_digest(new.encode(), request.form.get("confirm", "").encode()):
            flash("Passwords do not match.", "error")
        else:
            d.execute("UPDATE users SET password_hash = ? WHERE id = ?", (sl.hash_password(new), g.user["id"]))
            d.execute("DELETE FROM sessions WHERE user_id = ?", (g.user["id"],))
            d.commit()
            sl.audit(d, username, "PASSWORD_CHANGED")
            session.clear()
            flash("Password changed. Please log in again.", "success")
            return redirect(url_for("login"))
    return render_template("change_password.html")


@app.route("/logout", methods=["POST"])
def logout():
    token, user = session.get("token"), current_user()
    if token:
        sl.destroy_session(db(), token)
    if user:
        sl.audit(db(), user["username"], "LOGOUT")
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
