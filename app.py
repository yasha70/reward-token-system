"""
Reward Token System
-------------------
Generates barcode tokens for free food / gifts, and lets an admin at any
outlet scan a token to check whether it is VALID, FAKE, EXPIRED or ALREADY
CLAIMED, and then mark it as claimed.

How fake tokens are detected
  Every token code looks like  RW-XXXXXXXX-SSSSSS
    XXXXXXXX = random id
    SSSSSS   = HMAC-SHA256 signature of the id, made with a secret key
  A code is FAKE if its format is wrong, its signature does not match
  (someone made it up or changed a character), or it isn't in the database.
  Claiming uses a single atomic UPDATE, so one token can never be claimed
  twice, even if two outlets scan it at the same moment.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ON_VERCEL = bool(os.environ.get("VERCEL"))
# Postgres (required on Vercel), e.g. Neon from the Vercel Marketplace.
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
DB_PATH = os.environ.get("TOKEN_DB", os.path.join(BASE_DIR, "tokens.db"))  # local SQLite
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
APP_TIMEZONE = os.environ.get("APP_TIMEZONE")  # e.g. "Asia/Kolkata"; default = server time

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I to avoid misreads
CODE_RE = re.compile(r"^RW-([A-Z0-9]{8})-([A-F0-9]{6})$")

if DATABASE_URL:
    import psycopg
    from psycopg.rows import dict_row
    INTEGRITY_ERRORS = (psycopg.errors.UniqueViolation,)
else:
    if ON_VERCEL:
        raise RuntimeError("DATABASE_URL (Postgres) must be set on Vercel - SQLite files do not persist there.")
    INTEGRITY_ERRORS = (sqlite3.IntegrityError,)


def load_secret() -> bytes:
    env = os.environ.get("TOKEN_SECRET")
    if env:
        return env.encode()
    if ON_VERCEL:
        raise RuntimeError("TOKEN_SECRET must be set on Vercel.")
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(SECRET_FILE, 0o600)
    with open(SECRET_FILE) as f:
        return f.read().strip().encode()


SECRET = load_secret()

app = Flask(__name__, static_folder="public/static", static_url_path="/static")
app.secret_key = hashlib.sha256(SECRET + b"session").hexdigest()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=ON_VERCEL)


# ---------------------------------------------------------------- database
class Database:
    """Tiny wrapper so the same SQL (with ? placeholders) runs on SQLite or Postgres."""

    def __init__(self):
        if DATABASE_URL:
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row

    def execute(self, sql, args=()):
        if DATABASE_URL:
            sql = sql.replace("?", "%s")
        cur = self.conn.cursor()
        cur.execute(sql, args)
        return cur

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def db():
    if "db" not in g:
        g.db = Database()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS tokens (
        code           TEXT PRIMARY KEY,
        reward_type    TEXT NOT NULL,          -- 'Free Food' or 'Gift'
        reward_item    TEXT NOT NULL,
        customer       TEXT,
        phone          TEXT,
        issued_at      TEXT NOT NULL,
        issued_by      TEXT,
        expires_at     TEXT,
        status         TEXT NOT NULL DEFAULT 'active',  -- active | claimed | void
        claimed_at     TEXT,
        claimed_outlet TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS scan_log (
        id         %s,
        code       TEXT,
        result     TEXT,
        outlet     TEXT,
        scanned_at TEXT
    )""" % ("SERIAL PRIMARY KEY" if DATABASE_URL else "INTEGER PRIMARY KEY AUTOINCREMENT"),
]


def init_db():
    d = Database()
    for stmt in SCHEMA:
        d.execute(stmt)
    d.commit()
    d.close()


# ------------------------------------------------------------ token codes
def sign(token_id: str) -> str:
    return hmac.new(SECRET, token_id.encode(), hashlib.sha256).hexdigest()[:6].upper()


def new_code() -> str:
    token_id = "".join(secrets.choice(ALPHABET) for _ in range(8))
    return f"RW-{token_id}-{sign(token_id)}"


def signature_ok(code: str) -> bool:
    m = CODE_RE.match(code)
    return bool(m) and hmac.compare_digest(sign(m.group(1)), m.group(2))


def local_now() -> datetime:
    if APP_TIMEZONE:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(APP_TIMEZONE)).replace(tzinfo=None)
    return datetime.now()


def now() -> str:
    return local_now().strftime("%Y-%m-%d %H:%M:%S")


def token_dict(row):
    return dict(row) if row else None


def check_token(code: str):
    """Return (status, message, token) where status is one of
    VALID, CLAIMED, EXPIRED, VOID, FAKE."""
    code = code.strip().upper()
    if not CODE_RE.match(code):
        return "FAKE", "Not a valid token format.", None
    if not signature_ok(code):
        return "FAKE", "Security signature does not match - this token was not issued by us.", None
    row = db().execute("SELECT * FROM tokens WHERE code = ?", (code,)).fetchone()
    if row is None:
        return "FAKE", "Token not found in the system.", None
    t = token_dict(row)
    if t["status"] == "claimed":
        return "CLAIMED", f"Already claimed on {t['claimed_at']} at {t['claimed_outlet']}.", t
    if t["status"] == "void":
        return "VOID", "This token was cancelled by an admin.", t
    if t["expires_at"] and t["expires_at"] < now():
        return "EXPIRED", f"Token expired on {t['expires_at']}.", t
    return "VALID", "Genuine token - ready to be claimed.", t


def log_scan(code, result, outlet):
    db().execute(
        "INSERT INTO scan_log (code, result, outlet, scanned_at) VALUES (?,?,?,?)",
        (code[:64], result, outlet, now()),
    )
    db().commit()


# ------------------------------------------------------------------ auth
def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify(error="Login required"), 401
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if hmac.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session["admin"] = True
            session["outlet"] = request.form.get("outlet", "").strip() or "Main Outlet"
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") else "/")
        error = "Wrong password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------- pages
@app.route("/")
@login_required
def issue_page():
    return render_template("issue.html", page="issue")


@app.route("/verify")
@login_required
def verify_page():
    return render_template("verify.html", page="verify")


@app.route("/tokens")
@login_required
def tokens_page():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    sql, args = "SELECT * FROM tokens WHERE 1=1", []
    if q:
        sql += " AND (code LIKE ? OR customer LIKE ? OR phone LIKE ? OR reward_item LIKE ?)"
        args += [f"%{q}%"] * 4
    if status:
        sql += " AND status = ?"
        args.append(status)
    rows = db().execute(sql + " ORDER BY issued_at DESC LIMIT 500", args).fetchall()
    stats = {r["status"]: r["n"] for r in db().execute(
        "SELECT status, COUNT(*) n FROM tokens GROUP BY status")}
    fakes = db().execute("SELECT COUNT(*) AS n FROM scan_log WHERE result='FAKE'").fetchone()["n"]
    return render_template("tokens.html", page="tokens", rows=rows, q=q,
                           status=status, stats=stats, fakes=fakes, now=now())


@app.route("/token/<code>")
@login_required
def ticket_page(code):
    row = db().execute("SELECT * FROM tokens WHERE code = ?", (code.upper(),)).fetchone()
    if not row:
        abort(404)
    return render_template("ticket.html", t=token_dict(row))


# ------------------------------------------------------------------- API
@app.post("/api/tokens")
@login_required
def api_issue():
    d = request.get_json(force=True)
    reward_type = d.get("reward_type") if d.get("reward_type") in ("Free Food", "Gift") else "Free Food"
    item = (d.get("reward_item") or "").strip()[:120]
    if not item:
        return jsonify(error="Please describe the food / gift."), 400
    try:
        qty = max(1, min(int(d.get("quantity", 1)), 100))
        days = int(d.get("valid_days", 30))
    except ValueError:
        return jsonify(error="Invalid number."), 400
    expires = (local_now() + timedelta(days=days)).strftime("%Y-%m-%d 23:59:59") if days > 0 else None

    codes = []
    for _ in range(qty):
        while True:
            code = new_code()
            try:
                db().execute(
                    "INSERT INTO tokens (code, reward_type, reward_item, customer, phone,"
                    " issued_at, issued_by, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                    (code, reward_type, item, (d.get("customer") or "").strip()[:80],
                     (d.get("phone") or "").strip()[:20], now(), session.get("outlet"), expires),
                )
                break
            except INTEGRITY_ERRORS:
                db().rollback()
                continue  # astronomically unlikely collision; try again
        codes.append(code)
    db().commit()
    return jsonify(codes=codes)


@app.post("/api/verify")
@login_required
def api_verify():
    code = (request.get_json(force=True).get("code") or "").strip().upper()
    status, message, token = check_token(code)
    log_scan(code, status, session.get("outlet"))
    return jsonify(status=status, message=message, token=token, code=code)


@app.post("/api/claim")
@login_required
def api_claim():
    code = (request.get_json(force=True).get("code") or "").strip().upper()
    status, message, token = check_token(code)
    if status != "VALID":
        return jsonify(status=status, message=message, token=token, code=code), 409
    outlet = session.get("outlet")
    # Atomic: only succeeds if the token is still active.
    cur = db().execute(
        "UPDATE tokens SET status='claimed', claimed_at=?, claimed_outlet=?"
        " WHERE code=? AND status='active'", (now(), outlet, code))
    db().commit()
    if cur.rowcount != 1:
        status, message, token = check_token(code)
        return jsonify(status=status, message=message, token=token, code=code), 409
    log_scan(code, "CLAIMED_NOW", outlet)
    token = token_dict(db().execute("SELECT * FROM tokens WHERE code=?", (code,)).fetchone())
    return jsonify(status="CLAIMED_NOW", message=f"Successfully claimed at {outlet}. Hand over the reward.",
                   token=token, code=code)


@app.post("/api/void")
@login_required
def api_void():
    code = (request.get_json(force=True).get("code") or "").strip().upper()
    db().execute("UPDATE tokens SET status='void' WHERE code=? AND status='active'", (code,))
    db().commit()
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    if ADMIN_PASSWORD == "admin123":
        print("WARNING: using default admin password 'admin123'. Set ADMIN_PASSWORD env var.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
