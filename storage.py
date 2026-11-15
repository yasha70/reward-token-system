"""
Storage backends for the reward token app.

  RedisStore  - Upstash Redis over its REST API (Vercel KV / Upstash integration).
                Used when KV_REST_API_URL + KV_REST_API_TOKEN are set.
  SQLStore    - Postgres (DATABASE_URL / POSTGRES_URL) or a local SQLite file.

Both expose the same methods, and claiming / cancelling is atomic in both,
so a token can never be claimed twice.
"""
import json
import sqlite3
import time
import urllib.error
import urllib.request

TOKEN_FIELDS = ["code", "reward_type", "reward_item", "customer", "phone", "issued_at",
                "issued_by", "expires_at", "status", "claimed_at", "claimed_outlet"]
NULLABLE = {"customer", "phone", "expires_at", "claimed_at", "claimed_outlet", "issued_by"}


class StoreError(Exception):
    pass


# --------------------------------------------------------------------- Redis
class RedisStore:
    kind = "redis (upstash)"

    INSERT_LUA = """
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('ZADD', KEYS[2], ARGV[1], ARGV[2])
redis.call('HINCRBY', KEYS[3], 'active', 1)
return 1"""

    # ARGV[1] = new status, ARGV[2..] = extra field/value pairs
    TRANSITION_LUA = """
if redis.call('HGET', KEYS[1], 'status') ~= 'active' then return 0 end
redis.call('HSET', KEYS[1], 'status', ARGV[1])
if #ARGV > 1 then redis.call('HSET', KEYS[1], unpack(ARGV, 2)) end
redis.call('HINCRBY', KEYS[2], 'active', -1)
redis.call('HINCRBY', KEYS[2], ARGV[1], 1)
return 1"""

    def __init__(self, url, token, prefix="rwtok:"):
        self.url = url.rstrip("/")
        self.token = token
        self.p = prefix
        self.k_idx, self.k_stats = prefix + "idx", prefix + "stats"
        self.k_fakes, self.k_log = prefix + "fakes", prefix + "log"

    def _key(self, code):
        return f"{self.p}t:{code}"

    def _post(self, path, payload):
        req = urllib.request.Request(
            self.url + path, data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:200]
            raise StoreError(f"Upstash HTTP {e.code}: {body}") from None
        except urllib.error.URLError as e:
            raise StoreError(f"Cannot reach Upstash: {e.reason}") from None

    def cmd(self, *args):
        res = self._post("", [str(a) for a in args])
        if "error" in res:
            raise StoreError(res["error"])
        return res.get("result")

    def pipeline(self, commands):
        if not commands:
            return []
        out = []
        for i in range(0, len(commands), 100):
            res = self._post("/pipeline", [[str(a) for a in c] for c in commands[i:i + 100]])
            for r in res:
                if "error" in r:
                    raise StoreError(r["error"])
                out.append(r.get("result"))
        return out

    @staticmethod
    def _pairs(flat):
        """Upstash returns HGETALL as a flat [k1, v1, k2, v2, ...] list."""
        if isinstance(flat, dict):
            return flat
        return dict(zip(flat[0::2], flat[1::2])) if flat else {}

    @classmethod
    def _to_token(cls, flat):
        d = cls._pairs(flat)
        if not d:
            return None
        t = {f: d.get(f, "") for f in TOKEN_FIELDS}
        for f in NULLABLE:
            t[f] = t[f] or None
        return t

    # -- interface
    def init(self):
        self.cmd("PING")

    def insert_token(self, t):
        fields = []
        for f in TOKEN_FIELDS:
            fields += [f, "" if t.get(f) is None else t[f]]
        return self.cmd("EVAL", self.INSERT_LUA, 3, self._key(t["code"]), self.k_idx, self.k_stats,
                        f"{time.time():.6f}", t["code"], *fields) == 1

    def get_token(self, code):
        return self._to_token(self.cmd("HGETALL", self._key(code)))

    def claim(self, code, at, outlet):
        return self.cmd("EVAL", self.TRANSITION_LUA, 2, self._key(code), self.k_stats,
                        "claimed", "claimed_at", at, "claimed_outlet", outlet or "") == 1

    def void(self, code):
        return self.cmd("EVAL", self.TRANSITION_LUA, 2, self._key(code), self.k_stats, "void") == 1

    def log_scan(self, code, result, outlet, at):
        cmds = [["LPUSH", self.k_log, json.dumps([at, code[:64], result, outlet])],
                ["LTRIM", self.k_log, 0, 4999]]
        if result == "FAKE":
            cmds.append(["INCR", self.k_fakes])
        self.pipeline(cmds)

    def list_tokens(self, q="", status="", limit=500, scan=2000):
        """Newest first. Searches the most recent `scan` tokens."""
        codes = self.cmd("ZREVRANGE", self.k_idx, 0, scan - 1) or []
        rows = [self._to_token(f) for f in self.pipeline([["HGETALL", self._key(c)] for c in codes])]
        ql = q.lower()
        out = []
        for t in rows:
            if not t or (status and t["status"] != status):
                continue
            if ql and not any(ql in (t[f] or "").lower() for f in ("code", "customer", "phone", "reward_item")):
                continue
            out.append(t)
            if len(out) >= limit:
                break
        return out

    def stats(self):
        return {k: int(v) for k, v in self._pairs(self.cmd("HGETALL", self.k_stats)).items()}

    def fake_count(self):
        return int(self.cmd("GET", self.k_fakes) or 0)

    def close(self):
        pass


# ----------------------------------------------------------------------- SQL
class SQLStore:
    def __init__(self, database_url=None, sqlite_path=None):
        self.pg = bool(database_url)
        self.kind = "postgres" if self.pg else "sqlite"
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row
            self.integrity = psycopg.errors.UniqueViolation
            self.conn = psycopg.connect(database_url, row_factory=dict_row)
        else:
            self.integrity = sqlite3.IntegrityError
            self.conn = sqlite3.connect(sqlite_path)
            self.conn.row_factory = sqlite3.Row

    def _x(self, sql, args=()):
        if self.pg:
            sql = sql.replace("?", "%s")
        cur = self.conn.cursor()
        cur.execute(sql, args)
        return cur

    def init(self):
        self._x("""CREATE TABLE IF NOT EXISTS tokens (
            code TEXT PRIMARY KEY, reward_type TEXT NOT NULL, reward_item TEXT NOT NULL,
            customer TEXT, phone TEXT, issued_at TEXT NOT NULL, issued_by TEXT, expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'active', claimed_at TEXT, claimed_outlet TEXT)""")
        self._x("""CREATE TABLE IF NOT EXISTS scan_log (id %s, code TEXT, result TEXT,
            outlet TEXT, scanned_at TEXT)""" %
                ("SERIAL PRIMARY KEY" if self.pg else "INTEGER PRIMARY KEY AUTOINCREMENT"))
        self.conn.commit()

    def insert_token(self, t):
        try:
            self._x("INSERT INTO tokens (" + ",".join(TOKEN_FIELDS) + ") VALUES (" +
                    ",".join("?" * len(TOKEN_FIELDS)) + ")", [t.get(f) for f in TOKEN_FIELDS])
            self.conn.commit()
            return True
        except self.integrity:
            self.conn.rollback()
            return False

    def get_token(self, code):
        row = self._x("SELECT * FROM tokens WHERE code = ?", (code,)).fetchone()
        return dict(row) if row else None

    def claim(self, code, at, outlet):
        cur = self._x("UPDATE tokens SET status='claimed', claimed_at=?, claimed_outlet=? "
                      "WHERE code=? AND status='active'", (at, outlet, code))
        self.conn.commit()
        return cur.rowcount == 1

    def void(self, code):
        cur = self._x("UPDATE tokens SET status='void' WHERE code=? AND status='active'", (code,))
        self.conn.commit()
        return cur.rowcount == 1

    def log_scan(self, code, result, outlet, at):
        self._x("INSERT INTO scan_log (code, result, outlet, scanned_at) VALUES (?,?,?,?)",
                (code[:64], result, outlet, at))
        self.conn.commit()

    def list_tokens(self, q="", status="", limit=500):
        sql, args = "SELECT * FROM tokens WHERE 1=1", []
        if q:
            sql += (" AND (LOWER(code) LIKE ? OR LOWER(customer) LIKE ? OR LOWER(phone) LIKE ?"
                    " OR LOWER(reward_item) LIKE ?)")
            args += [f"%{q.lower()}%"] * 4
        if status:
            sql += " AND status = ?"
            args.append(status)
        return [dict(r) for r in self._x(sql + f" ORDER BY issued_at DESC LIMIT {int(limit)}", args)]

    def stats(self):
        return {r["status"]: r["n"] for r in
                self._x("SELECT status, COUNT(*) AS n FROM tokens GROUP BY status")}

    def fake_count(self):
        return self._x("SELECT COUNT(*) AS n FROM scan_log WHERE result='FAKE'").fetchone()["n"]

    def close(self):
        self.conn.close()
