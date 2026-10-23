#!/usr/bin/env python3
"""
Secure Login System - Cyber Security Project (single file, standard library only)

Security features:
  1. Password hashing with scrypt (memory-hard) + unique 16-byte random salt
  2. Optional server-side "pepper" (set env var APP_PEPPER) applied via HMAC
  3. Constant-time comparisons (hmac.compare_digest) - prevents timing attacks
  4. Parameterized SQL queries - prevents SQL injection
  5. Strong password policy + common-password blocklist
  6. Account lockout after repeated failed logins (brute-force protection)
  7. Generic error messages + dummy hash check - prevents user enumeration
  8. Optional TOTP two-factor authentication (RFC 6238, Google Authenticator compatible)
  9. Session tokens (secrets module), stored only as SHA-256 hashes, with expiry
 10. Audit log of security events
 11. Hidden password input (getpass)

Run:  python secure_login.py
"""

import base64
import getpass
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time

# ------------------------------------------------------------------ CONFIG
DB_PATH = "secure_login.db"
SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN = 2 ** 14, 8, 1, 32
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300          # 5 minutes
SESSION_TTL_SECONDS = 900      # 15 minutes
PEPPER = os.environ.get("APP_PEPPER", "").encode()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwerty123", "qwertyuiop", "iloveyou", "admin123", "welcome1",
    "letmein123", "abc12345", "p@ssw0rd", "p@ssword1",
}


# ---------------------------------------------------------------- DATABASE
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until REAL NOT NULL DEFAULT 0,
        totp_secret TEXT,
        created_at REAL NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at REAL NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        username TEXT,
        event TEXT NOT NULL)""")
    db.commit()
    return db


def audit(db, username, event):
    db.execute("INSERT INTO audit_log (ts, username, event) VALUES (?, ?, ?)",
               (time.strftime("%Y-%m-%d %H:%M:%S"), username, event))
    db.commit()


# ------------------------------------------------------- PASSWORD HASHING
def _derive(password: str, salt: bytes, n, r, p) -> bytes:
    # HMAC with pepper (if set) so a stolen DB alone is not enough to crack hashes
    pre = hmac.new(PEPPER, password.encode(), hashlib.sha256).digest() if PEPPER \
        else password.encode()
    return hashlib.scrypt(pre, salt=salt, n=n, r=r, p=p,
                          dklen=KEY_LEN, maxmem=128 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return "$".join(["scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P),
                     base64.b64encode(salt).decode(),
                     base64.b64encode(digest).decode()])


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_b64, hash_b64 = stored.split("$")
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
        actual = _derive(password, salt, int(n), int(r), int(p))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# Used for non-existent users so response time looks the same (anti-enumeration)
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def validate_password(password: str, username: str = ""):
    """Return list of problems (empty list = OK)."""
    problems = []
    if len(password) < 12:
        problems.append("at least 12 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a special character")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("not be a commonly used password")
    if username and username.lower() in password.lower():
        problems.append("not contain your username")
    return problems


# -------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    counter = int(time.time()) // 30
    return any(hmac.compare_digest(_totp_at(secret, counter + d), code.strip())
               for d in range(-window, window + 1))


# ---------------------------------------------------------------- SESSIONS
def create_session(db, user_id) -> str:
    token = secrets.token_urlsafe(32)
    db.execute("INSERT INTO sessions VALUES (?, ?, ?)",
               (hashlib.sha256(token.encode()).hexdigest(), user_id,
                time.time() + SESSION_TTL_SECONDS))
    db.commit()
    return token


def validate_session(db, token):
    """Return user_id if the session is valid, else None."""
    row = db.execute("SELECT user_id, expires_at FROM sessions WHERE token_hash = ?",
                     (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if row and row[1] > time.time():
        return row[0]
    return None


def destroy_session(db, token):
    db.execute("DELETE FROM sessions WHERE token_hash = ?",
               (hashlib.sha256(token.encode()).hexdigest(),))
    db.commit()


# ------------------------------------------------------------ CORE ACTIONS
def register(db):
    username = input("Choose username (3-20 letters/digits/_): ").strip()
    if not USERNAME_RE.match(username):
        print("[-] Invalid username format.")
        return
    password = getpass.getpass("Choose password: ")
    problems = validate_password(password, username)
    if problems:
        print("[-] Password must have: " + ", ".join(problems))
        return
    if not hmac.compare_digest(password, getpass.getpass("Confirm password: ")):
        print("[-] Passwords do not match.")
        return
    try:
        db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                   (username, hash_password(password), time.time()))
        db.commit()
        audit(db, username, "REGISTER_SUCCESS")
        print("[+] Account created. You can now log in.")
    except sqlite3.IntegrityError:
        print("[-] Registration failed. Try a different username.")


def login(db):
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    row = db.execute("SELECT id, password_hash, failed_attempts, locked_until, totp_secret "
                     "FROM users WHERE username = ?", (username,)).fetchone()

    if row is None:
        verify_password(password, DUMMY_HASH)   # equalise timing
        audit(db, username, "LOGIN_FAIL_UNKNOWN_USER")
        print("[-] Invalid username or password.")
        return None

    user_id, pw_hash, failed, locked_until, totp_secret = row

    if locked_until > time.time():
        wait = int(locked_until - time.time())
        audit(db, username, "LOGIN_BLOCKED_LOCKED")
        print(f"[-] Account temporarily locked. Try again in {wait} seconds.")
        return None

    if not verify_password(password, pw_hash):
        failed += 1
        if failed >= MAX_FAILED_ATTEMPTS:
            db.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                       (time.time() + LOCKOUT_SECONDS, user_id))
            audit(db, username, "ACCOUNT_LOCKED")
        else:
            db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, user_id))
            audit(db, username, "LOGIN_FAIL_BAD_PASSWORD")
        db.commit()
        print("[-] Invalid username or password.")
        return None

    if totp_secret:
        if not verify_totp(totp_secret, input("2FA code: ")):
            audit(db, username, "LOGIN_FAIL_BAD_2FA")
            print("[-] Invalid 2FA code.")
            return None

    db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user_id,))
    db.commit()
    audit(db, username, "LOGIN_SUCCESS")
    print(f"[+] Welcome, {username}!")
    return create_session(db, user_id), username


def enable_2fa(db, user_id, username):
    secret = new_totp_secret()
    print("\nAdd this secret to Google Authenticator / Authy (manual entry, time-based):")
    print(f"    {secret}\n")
    if verify_totp(secret, input("Enter the 6-digit code to confirm: ")):
        db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
        db.commit()
        audit(db, username, "2FA_ENABLED")
        print("[+] 2FA enabled.")
    else:
        print("[-] Code incorrect. 2FA not enabled.")


def change_password(db, user_id, username):
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    if not verify_password(getpass.getpass("Current password: "), row[0]):
        audit(db, username, "PASSWORD_CHANGE_FAIL")
        print("[-] Current password incorrect.")
        return
    new = getpass.getpass("New password: ")
    problems = validate_password(new, username)
    if problems:
        print("[-] Password must have: " + ", ".join(problems))
        return
    if not hmac.compare_digest(new, getpass.getpass("Confirm new password: ")):
        print("[-] Passwords do not match.")
        return
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user_id))
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))  # revoke all sessions
    db.commit()
    audit(db, username, "PASSWORD_CHANGED")
    print("[+] Password changed. Please log in again.")


def view_audit(db, username):
    rows = db.execute("SELECT ts, event FROM audit_log WHERE username = ? "
                      "ORDER BY id DESC LIMIT 10", (username,)).fetchall()
    print("\nLast 10 security events:")
    for ts, ev in rows:
        print(f"  {ts}  {ev}")


# ------------------------------------------------------------------- MENUS
def user_menu(db, token, username):
    while True:
        user_id = validate_session(db, token)
        if user_id is None:
            print("[!] Session expired. Please log in again.")
            return
        print(f"\n--- Dashboard ({username}) ---")
        print("1) Enable 2FA\n2) Change password\n3) View my security log\n4) Logout")
        choice = input("> ").strip()
        if choice == "1":
            enable_2fa(db, user_id, username)
        elif choice == "2":
            change_password(db, user_id, username)
            if validate_session(db, token) is None:
                return
        elif choice == "3":
            view_audit(db, username)
        elif choice == "4":
            destroy_session(db, token)
            audit(db, username, "LOGOUT")
            print("[+] Logged out.")
            return


def main():
    db = get_db()
    if not PEPPER:
        print("[i] Tip: set APP_PEPPER env variable for an extra layer of hash protection.")
    while True:
        print("\n=== SECURE LOGIN SYSTEM ===\n1) Register\n2) Login\n3) Exit")
        choice = input("> ").strip()
        if choice == "1":
            register(db)
        elif choice == "2":
            result = login(db)
            if result:
                user_menu(db, *result)
        elif choice == "3":
            break
    db.close()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
