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
  Claiming is atomic in every storage backend (see storage.py), so one token
  can never be claimed twice, even if two outlets scan it at the same moment.

Storage: Upstash Redis (KV_REST_API_URL/TOKEN), Postgres (DATABASE_URL) or,
locally, a SQLite file.
"""
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)

from storage import RedisStore, SQLStore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ON_VERCEL = bool(os.environ.get("VERCEL"))
DB_PATH = os.environ.get("TOKEN_DB", os.path.join(BASE_DIR, "tokens.db"))  # local SQLite
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or ("" if ON_VERCEL else "admin123")
APP_TIMEZONE = (os.environ.get("APP_TIMEZONE") or "").strip() or None  # e.g. "Asia/Kolkata"

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I to avoid misreads
CODE_RE = re.compile(r"^RW-([A-Z0-9]{8})-([A-F0-9]{6})$")

# Problems that stop the app from working. Shown on every page (and /health)
# instead of crashing, so it is obvious what to fix in the Vercel settings.
CONFIG_ERRORS = []


def find_database_url():
    """Postgres connection string. Vercel's Neon integration sets DATABASE_URL /
    POSTGRES_URL, or <PREFIX>_DATABASE_URL when a custom prefix was chosen."""
    for name in ("DATABASE_URL", "POSTGRES_URL"):
        if os.environ.get(name):
            return os.environ[name].strip()
    for name, value in sorted(os.environ.items()):
        if name.endswith(("_DATABASE_URL", "_POSTGRES_URL")) and value.startswith(("postgres://", "postgresql://")):
            return value.strip()
    return None


DATABASE_URL = find_database_url()
# Upstash Redis via Vercel's Upstash/KV integration (or Upstash directly).
REDIS_REST_URL = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
REDIS_REST_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
USE_REDIS = bool(REDIS_REST_URL and REDIS_REST_TOKEN)

if USE_REDIS:
    BACKEND = "redis (upstash)"
elif DATABASE_URL:
    BACKEND = "postgres"
    try:
        import psycopg  # noqa: F401
    except Exception as e:
        CONFIG_ERRORS.append(f"Postgres driver failed to load: {type(e).__name__}: {e}")
else:
    BACKEND = "sqlite"
    if ON_VERCEL:
        CONFIG_ERRORS.append(
            "No database connected. In Vercel open Storage and connect an Upstash Redis or "
            "Neon Postgres database to this project, then Redeploy.")

if ON_VERCEL and not ADMIN_PASSWORD:
    CONFIG_ERRORS.append("ADMIN_PASSWORD is not set. Add it in Settings -> Environment Variables, then Redeploy.")

if APP_TIMEZONE:
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(APP_TIMEZONE)
    except Exception:
        CONFIG_ERRORS.append(f"APP_TIMEZONE '{APP_TIMEZONE}' is not a valid time zone. "
                             "Use a name like Asia/Kolkata, then Redeploy.")


def load_secret() -> bytes:
    env = (os.environ.get("TOKEN_SECRET") or "").strip()
    if env:
        return env.encode()
    if ON_VERCEL:
        CONFIG_ERRORS.append("TOKEN_SECRET is not set. Add a long random value in Settings -> "
                             "Environment Variables, then Redeploy.")
        return secrets.token_hex(32).encode()  # placeholder; requests are blocked anyway
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
def make_store():
    if USE_REDIS:
        return RedisStore(REDIS_REST_URL, REDIS_REST_TOKEN)
    return SQLStore(DATABASE_URL, DB_PATH)


def store():
    if "store" not in g:
        g.store = make_store()
    return g.store


@app.teardown_appcontext
def close_store(_exc):
    st = g.pop("store", None)
    if st is not None:
        st.close()


_db_ready = False


def init_db():
    """Prepare storage once per server instance. Returns an error string or None."""
    global _db_ready
    if _db_ready:
        return None
    try:
        st = make_store()
        st.init()
        st.close()
        _db_ready = True
        return None
    except Exception as e:  # report it on the page instead of a bare 500
        msg = str(e).strip().splitlines()[0] if str(e).strip() else ""
        for secret in (DATABASE_URL, REDIS_REST_TOKEN):
            if secret:
                msg = msg.replace(secret, "<hidden>")
        return f"Cannot connect to the database ({type(e).__name__}: {msg[:200]})"


SETUP_PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Setup needed</title><body style="font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#1d2330">
<h1 style="color:#dc2626">Setup needed</h1><p>The app is deployed but not configured yet:</p><ul>{items}</ul>
<p style="color:#6b7280">After changing environment variables on Vercel, open <b>Deployments &rarr; &hellip; &rarr; Redeploy</b>.</p></body>"""


def problems():
    errs = list(CONFIG_ERRORS)
    if not errs:
        err = init_db()
        if err:
            errs.append(err)
    return errs


@app.before_request
def require_setup():
    if request.path == "/health" or request.path.startswith("/static/"):
        return None
    errs = problems()
    if errs:
        from markupsafe import escape
        items = "".join(f"<li style='margin:8px 0'>{escape(e)}</li>" for e in errs)
        return SETUP_PAGE.format(items=items), 503


@app.route("/health")
def health():
    errs = problems()
    return jsonify(ok=not errs, problems=errs, on_vercel=ON_VERCEL,
                   database=BACKEND,
                   timezone=APP_TIMEZONE or "server default"), (200 if not errs else 503)


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


def check_token(code: str):
    """Return (status, message, token) where status is one of
    VALID, CLAIMED, EXPIRED, VOID, FAKE."""
    code = code.strip().upper()
    if not CODE_RE.match(code):
        return "FAKE", "Not a valid token format.", None
    if not signature_ok(code):
        return "FAKE", "Security signature does not match - this token was not issued by us.", None
    t = store().get_token(code)
    if t is None:
        return "FAKE", "Token not found in the system.", None
    if t["status"] == "claimed":
        return "CLAIMED", f"Already claimed on {t['claimed_at']} at {t['claimed_outlet']}.", t
    if t["status"] == "void":
        return "VOID", "This token was cancelled by an admin.", t
    if t["expires_at"] and t["expires_at"] < now():
        return "EXPIRED", f"Token expired on {t['expires_at']}.", t
    return "VALID", "Genuine token - ready to be claimed.", t


def log_scan(code, result, outlet):
    store().log_scan(code, result, outlet, now())


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
    rows = store().list_tokens(q=q, status=status)
    stats = store().stats()
    fakes = store().fake_count()
    return render_template("tokens.html", page="tokens", rows=rows, q=q,
                           status=status, stats=stats, fakes=fakes, now=now())


@app.route("/token/<code>")
@login_required
def ticket_page(code):
    t = store().get_token(code.upper())
    if not t:
        abort(404)
    return render_template("ticket.html", t=t)


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
            ok = store().insert_token({
                "code": code, "reward_type": reward_type, "reward_item": item,
                "customer": (d.get("customer") or "").strip()[:80],
                "phone": (d.get("phone") or "").strip()[:20],
                "issued_at": now(), "issued_by": session.get("outlet"), "expires_at": expires,
                "status": "active", "claimed_at": None, "claimed_outlet": None})
            if ok:
                break  # else: astronomically unlikely collision; try another code
        codes.append(code)
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
    if not store().claim(code, now(), outlet):
        status, message, token = check_token(code)
        return jsonify(status=status, message=message, token=token, code=code), 409
    log_scan(code, "CLAIMED_NOW", outlet)
    token = store().get_token(code)
    return jsonify(status="CLAIMED_NOW", message=f"Successfully claimed at {outlet}. Hand over the reward.",
                   token=token, code=code)


@app.post("/api/void")
@login_required
def api_void():
    code = (request.get_json(force=True).get("code") or "").strip().upper()
    store().void(code)
    return jsonify(ok=True)


if __name__ == "__main__":
    if ADMIN_PASSWORD == "admin123":
        print("WARNING: using default admin password 'admin123'. Set ADMIN_PASSWORD env var.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
