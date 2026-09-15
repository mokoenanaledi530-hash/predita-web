#!/usr/bin/env python3
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template_string,
    request, session, url_for
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("PREDITA_DB", "predita_cases.db")
ADMIN_USER = os.environ.get("PREDITA_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("PREDITA_ADMIN_PASSWORD")
SESSION_MINUTES = int(os.environ.get("PREDITA_SESSION_MINUTES", "30"))
HTTPS_ONLY = os.environ.get("PREDITA_HTTPS_ONLY", "0") == "1"
ALLOW_SELF_APPROVAL = os.environ.get("PREDITA_ALLOW_SELF_APPROVAL", "0") == "1"
SECRET_KEY = os.environ.get("PREDITA_SECRET_KEY") or secrets.token_hex(32)
UPLOAD_DIR = Path(os.environ.get("PREDITA_UPLOAD_DIR", "evidence_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MTN_CHECKS_ENABLED = os.environ.get("PREDITA_ENABLE_MTN_CHECKS", "0") == "1"
MTN_API_KEY = os.environ.get("MTN_API_KEY", "")
MTN_BEARER_TOKEN = os.environ.get("MTN_BEARER_TOKEN", "")
MTN_BASE_URL = os.environ.get("MTN_BASE_URL", "https://api.mtn.com")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = HTTPS_ONLY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_MINUTES)

BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · Predita</title>
<style>
:root { color-scheme: dark; --bg:#0b1220; --panel:#111a2b; --muted:#9fb0c8; --line:#26344c; --accent:#6ca8ff; --danger:#ff7b86; }
* { box-sizing:border-box; }
body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:#eef4ff; }
header { padding:16px 20px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:center; justify-content:space-between; }
header a { color:#fff; text-decoration:none; }
main { max-width:1180px; margin:0 auto; padding:22px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:16px; margin-bottom:16px; }
label { display:block; margin:9px 0 5px; color:var(--muted); }
input,select,button { width:100%; padding:11px 12px; border-radius:9px; border:1px solid var(--line); background:#0d1627; color:#fff; }
button { background:#1d5fae; cursor:pointer; font-weight:700; }
button.secondary { background:#172238; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th,td { padding:9px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; word-break:break-word; }
th { color:#bcd0ec; }
.small { font-size:12px; color:var(--muted); }
.badge { display:inline-block; border:1px solid var(--line); padding:3px 7px; border-radius:999px; color:#cfe0f7; }
.flash { padding:10px 12px; border-radius:9px; margin-bottom:12px; background:#163458; }
.err { background:#59202b; }
nav { display:flex; gap:12px; align-items:center; }
nav a { color:#cde0ff; }
code { color:#d6e6ff; }
@media(max-width:700px){ table{font-size:12px} main{padding:14px} }
</style>
</head>
<body>
<header>
  <div><strong>Predita</strong> <span class="small">authorized case-data workspace</span></div>
  {% if session.get('user') %}
  <nav>
    <span class="small">{{ session.get('role','') }}</span>
    <a href="{{ url_for('home') }}">Cases</a>
    {% if can('manage_users') %}<a href="{{ url_for('users_admin') }}">Users</a>{% endif %}
    <a href="{{ url_for('logout') }}">Sign out</a>
  </nav>
  {% endif %}
</header>
<main>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category,msg in messages %}
    <div class="flash {{ 'err' if category == 'error' else '' }}">{{ msg }}</div>
  {% endfor %}
{% endwith %}
{{ body|safe }}
</main>
</body>
</html>
"""

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL,
      last_login_at TEXT
    );

    CREATE TABLE IF NOT EXISTS cases (
      case_id TEXT PRIMARY KEY,
      authority_ref TEXT NOT NULL,
      title TEXT,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS imports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      dataset_type TEXT NOT NULL,
      provider TEXT NOT NULL,
      authority_ref TEXT NOT NULL,
      source_file TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      imported_at TEXT NOT NULL,
      row_count INTEGER NOT NULL DEFAULT 0,
      imported_by TEXT NOT NULL,
      UNIQUE(case_id, dataset_type, sha256),
      FOREIGN KEY(case_id) REFERENCES cases(case_id)
    );

    CREATE TABLE IF NOT EXISTS call_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      import_id INTEGER NOT NULL,
      provider TEXT NOT NULL,
      source_row INTEGER NOT NULL,
      a_number_raw TEXT, a_number_norm TEXT,
      b_number_raw TEXT, b_number_norm TEXT,
      event_time TEXT, duration_seconds INTEGER, direction TEXT,
      imei TEXT, imsi TEXT, cell_id TEXT, lac TEXT, tac TEXT,
      raw_json TEXT NOT NULL,
      FOREIGN KEY(case_id) REFERENCES cases(case_id),
      FOREIGN KEY(import_id) REFERENCES imports(id)
    );

    CREATE TABLE IF NOT EXISTS sms_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      import_id INTEGER NOT NULL,
      provider TEXT NOT NULL,
      source_row INTEGER NOT NULL,
      a_number_raw TEXT, a_number_norm TEXT,
      b_number_raw TEXT, b_number_norm TEXT,
      event_time TEXT, direction TEXT, message_type TEXT, delivery_status TEXT,
      imei TEXT, imsi TEXT, cell_id TEXT,
      raw_json TEXT NOT NULL,
      FOREIGN KEY(case_id) REFERENCES cases(case_id),
      FOREIGN KEY(import_id) REFERENCES imports(id)
    );

    CREATE TABLE IF NOT EXISTS subscriber_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      import_id INTEGER NOT NULL,
      provider TEXT NOT NULL,
      source_row INTEGER NOT NULL,
      id_number TEXT, id_valid INTEGER,
      msisdn_raw TEXT, msisdn_norm TEXT,
      subscriber_name TEXT, activation_date TEXT, status TEXT,
      sim_serial TEXT, imsi TEXT,
      raw_json TEXT NOT NULL,
      FOREIGN KEY(case_id) REFERENCES cases(case_id),
      FOREIGN KEY(import_id) REFERENCES imports(id)
    );

    CREATE TABLE IF NOT EXISTS evidence_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      dataset_type TEXT NOT NULL,
      provider TEXT NOT NULL,
      authority_ref TEXT NOT NULL,
      source_reference TEXT,
      original_filename TEXT NOT NULL,
      stored_path TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      received_at TEXT NOT NULL,
      received_by TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'received',
      approved_at TEXT,
      approved_by TEXT,
      import_id INTEGER,
      rejection_reason TEXT,
      notes TEXT,
      UNIQUE(case_id, sha256),
      FOREIGN KEY(case_id) REFERENCES cases(case_id),
      FOREIGN KEY(import_id) REFERENCES imports(id)
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_case_status
      ON evidence_receipts(case_id, status, received_at);

    CREATE TABLE IF NOT EXISTS provider_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      capability TEXT NOT NULL,
      msisdn_norm TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      requested_by TEXT NOT NULL,
      http_status INTEGER,
      provider_transaction_id TEXT,
      result_status TEXT NOT NULL,
      result_json TEXT,
      FOREIGN KEY(case_id) REFERENCES cases(case_id)
    );

    CREATE INDEX IF NOT EXISTS idx_provider_checks_case
      ON provider_checks(case_id, checked_at);

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_time TEXT NOT NULL,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      case_id TEXT,
      detail TEXT,
      remote_addr TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_call_case_time ON call_records(case_id,event_time);
    CREATE INDEX IF NOT EXISTS idx_call_case_a ON call_records(case_id,a_number_norm);
    CREATE INDEX IF NOT EXISTS idx_call_case_b ON call_records(case_id,b_number_norm);
    CREATE INDEX IF NOT EXISTS idx_sms_case_time ON sms_records(case_id,event_time);
    CREATE INDEX IF NOT EXISTS idx_sms_case_a ON sms_records(case_id,a_number_norm);
    CREATE INDEX IF NOT EXISTS idx_sms_case_b ON sms_records(case_id,b_number_norm);
    CREATE INDEX IF NOT EXISTS idx_sub_case_number ON subscriber_records(case_id,msisdn_norm);
    CREATE INDEX IF NOT EXISTS idx_sub_case_id ON subscriber_records(case_id,id_number);
    """)
    # Non-destructive migration for databases created by Predita v1-v3 / CLI tools.
    def ensure_column(table, column, declaration):
        existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    ensure_column("cases", "title", "TEXT")
    ensure_column("cases", "created_by", "TEXT NOT NULL DEFAULT 'legacy'")
    ensure_column("imports", "dataset_type", "TEXT NOT NULL DEFAULT 'legacy'")
    ensure_column("imports", "imported_by", "TEXT NOT NULL DEFAULT 'legacy'")

    con.commit()


ROLE_PERMISSIONS = {
    "admin": {
        "view_case", "create_case", "validate_id", "receive_evidence",
        "approve_evidence", "search_case", "provider_check", "manage_users"
    },
    "intake": {"view_case", "create_case", "validate_id", "receive_evidence"},
    "investigator": {"view_case", "create_case", "validate_id", "search_case", "provider_check"},
    "approver": {"view_case", "search_case", "approve_evidence"},
}

def bootstrap_admin():
    """Create the first local admin only when no users exist and an env password is supplied."""
    con = db()
    count = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if count == 0 and ADMIN_PASSWORD:
        con.execute("""
          INSERT INTO users(username,password_hash,role,active,created_at,created_by)
          VALUES(?,?,?,?,?,?)
        """, (
            ADMIN_USER,
            generate_password_hash(ADMIN_PASSWORD),
            "admin", 1, now_iso(), "bootstrap"
        ))
        con.commit()

# Initialize on module import as well as direct execution. This is required for Gunicorn.
init_db()
bootstrap_admin()

def can(permission):
    role = session.get("role")
    return permission in ROLE_PERMISSIONS.get(role, set())

app.jinja_env.globals["can"] = can

def require_permission(permission):
    from functools import wraps
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user"):
                return redirect(url_for("login", next=request.path))
            if not can(permission):
                audit("permission_denied", kwargs.get("case_id"), f"permission={permission}")
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

@app.before_request
def refresh_session_security():
    if session.get("user"):
        # Flask permanent-session expiry handles inactivity between requests.
        session.permanent = True
        con = db()
        row = con.execute(
            "SELECT role,active FROM users WHERE username=?",
            (session["user"],)
        ).fetchone()
        if not row or not row["active"]:
            session.clear()
            if request.endpoint not in {"login", "static"}:
                return redirect(url_for("login"))
        else:
            session["role"] = row["role"]

def render_page(title, body_template, **ctx):
    body = render_template_string(body_template, **ctx)
    return render_template_string(BASE_HTML, title=title, body=body)

def audit(action, case_id=None, detail=None):
    con = db()
    con.execute(
        "INSERT INTO audit_events(event_time,username,action,case_id,detail,remote_addr) VALUES(?,?,?,?,?,?)",
        (now_iso(), session.get("user","anonymous"), action, case_id, detail, request.remote_addr),
    )
    con.commit()

def require_login(fn):
    from functools import wraps
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

def check_csrf():
    token = request.form.get("csrf","")
    if not token or not hmac.compare_digest(token, session.get("csrf","")):
        abort(400, "Invalid CSRF token")

def normalize_phone(raw):
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    digits = re.sub(r"\D", "", s)
    if digits.startswith("27") and len(digits) >= 11:
        return "+" + digits
    if digits.startswith("0") and len(digits) == 10:
        return "+27" + digits[1:]
    if s.startswith("+") and digits:
        return "+" + digits
    return digits or None

def luhn_valid(number):
    digits = [int(c) for c in number]
    total = 0
    parity = len(digits) % 2
    for i,d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9: d -= 9
        total += d
    return total % 10 == 0

def validate_sa_id(value):
    s = re.sub(r"\D", "", str(value or ""))
    result = {"normalized": s, "valid": False, "date_ok": False, "luhn_ok": False,
              "citizenship":"Unknown", "gender":"Unknown"}
    if len(s) != 13:
        return result
    yy,mm,dd = int(s[:2]), int(s[2:4]), int(s[4:6])
    for century in (1900,2000):
        try:
            datetime(century+yy,mm,dd)
            result["date_ok"] = True
            break
        except ValueError:
            pass
    result["gender"] = "Male" if int(s[6:10]) >= 5000 else "Female"
    result["citizenship"] = {"0":"South African citizen","1":"Permanent resident"}.get(s[10],"Unknown")
    result["luhn_ok"] = luhn_valid(s)
    result["valid"] = result["date_ok"] and result["luhn_ok"] and s[10] in {"0","1"}
    return result

def first_value(row, keys):
    low = {str(k).strip().lower(): v for k,v in row.items()}
    for k in keys:
        if k in low and str(low[k]).strip():
            return str(low[k]).strip()
    return None

def parse_duration(v):
    if not v: return None
    s = str(v).strip()
    if s.isdigit(): return int(s)
    try:
        parts = [int(x) for x in s.split(":")]
        if len(parts)==3: return parts[0]*3600+parts[1]*60+parts[2]
        if len(parts)==2: return parts[0]*60+parts[1]
    except ValueError:
        pass
    return None

def normalize_time(v):
    if not v: return None
    s = str(v).strip()
    try:
        return datetime.fromisoformat(s.replace("Z","+00:00")).isoformat()
    except ValueError:
        return s

def file_sha(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def mtn_sim_swap_date(msisdn):
    """
    Official MTN Mobile Customer Information operation.
    Calls only when explicitly enabled and credentials are present.
    """
    if not MTN_CHECKS_ENABLED:
        return {
            "ok": False,
            "status": "disabled",
            "message": "MTN checks are disabled. Set PREDITA_ENABLE_MTN_CHECKS=1 after approved onboarding."
        }

    number = normalize_phone(msisdn)
    if not number or not number.startswith("+"):
        return {"ok": False, "status": "invalid_number", "message": "Enter a valid E.164-compatible mobile number."}

    # MTN swagger identifies subscriberId as E.164. The path value is sent without spaces.
    subscriber_id = number
    url = f"{MTN_BASE_URL.rstrip('/')}/v1/mobile/subscribers/{subscriber_id}/simswap-date"

    headers = {
        "Accept": "application/json",
        "transactionId": secrets.token_hex(16),
    }
    if MTN_API_KEY:
        headers["X-API-Key"] = MTN_API_KEY
    elif MTN_BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {MTN_BEARER_TOKEN}"
    else:
        return {
            "ok": False,
            "status": "missing_credentials",
            "message": "Set MTN_API_KEY or MTN_BEARER_TOKEN on the server."
        }

    try:
        response = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status": "network_error",
            "message": str(exc),
            "http_status": None
        }

    try:
        payload = response.json()
    except ValueError:
        payload = {"raw_text": response.text[:2000]}

    # Never include request credentials in the stored/returned object.
    result = {
        "ok": response.ok,
        "status": "success" if response.ok else "provider_error",
        "http_status": response.status_code,
        "payload": payload,
        "provider_transaction_id": (
            payload.get("transactionId") if isinstance(payload, dict) else None
        ),
    }
    if response.ok and isinstance(payload, dict):
        data = payload.get("data") or {}
        result["last_sim_swap_date"] = data.get("lastSimSwapDate")
        # MTN documents empty date as "cannot be determined", not "no swap".
        if result["last_sim_swap_date"] == "":
            result["last_sim_swap_date"] = None
            result["status"] = "unknown_date"
    return result

def require_case(case_id):
    con = db()
    row = con.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if not row: abort(404)
    return row

def create_import(con, case_id, dataset, provider, authority, path):
    digest = file_sha(path)
    dup = con.execute(
        "SELECT id FROM imports WHERE case_id=? AND dataset_type=? AND sha256=?",
        (case_id,dataset,digest)
    ).fetchone()
    if dup:
        raise ValueError(f"Identical evidence already imported as import #{dup['id']}.")
    cur = con.execute("""
      INSERT INTO imports(case_id,dataset_type,provider,authority_ref,source_file,sha256,imported_at,row_count,imported_by)
      VALUES(?,?,?,?,?,?,?,?,?)
    """,(case_id,dataset,provider,authority,path.name,digest,now_iso(),0,session["user"]))
    return cur.lastrowid,digest

def import_csv(case_id, dataset, provider, authority, path):
    con = db()
    import_id,digest = create_import(con,case_id,dataset,provider,authority,path)
    count=0
    with open(path,"r",encoding="utf-8-sig",newline="") as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row.")
        for row_no,row in enumerate(reader,start=2):
            if dataset=="calls":
                a=first_value(row,["a_number","calling_number","caller","from","origin","source_number","msisdn_a","calling_party"])
                b=first_value(row,["b_number","called_number","callee","to","destination","target_number","msisdn_b","called_party"])
                con.execute("""INSERT INTO call_records(
                  case_id,import_id,provider,source_row,a_number_raw,a_number_norm,b_number_raw,b_number_norm,
                  event_time,duration_seconds,direction,imei,imsi,cell_id,lac,tac,raw_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(
                  case_id,import_id,provider,row_no,a,normalize_phone(a),b,normalize_phone(b),
                  normalize_time(first_value(row,["event_time","timestamp","datetime","start_time","date_time","call_time"])),
                  parse_duration(first_value(row,["duration","duration_seconds","seconds","call_duration"])),
                  first_value(row,["direction","call_direction","type"]),
                  first_value(row,["imei","device_imei"]), first_value(row,["imsi","subscriber_imsi"]),
                  first_value(row,["cell_id","cellid","cgi","eci"]),
                  first_value(row,["lac","location_area_code"]), first_value(row,["tac","tracking_area_code"]),
                  json.dumps(row,ensure_ascii=False)))
            elif dataset=="sms":
                a=first_value(row,["a_number","sender","from","source_number","origin","calling_number","msisdn_a"])
                b=first_value(row,["b_number","recipient","to","destination","target_number","called_number","msisdn_b"])
                con.execute("""INSERT INTO sms_records(
                  case_id,import_id,provider,source_row,a_number_raw,a_number_norm,b_number_raw,b_number_norm,
                  event_time,direction,message_type,delivery_status,imei,imsi,cell_id,raw_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(
                  case_id,import_id,provider,row_no,a,normalize_phone(a),b,normalize_phone(b),
                  normalize_time(first_value(row,["event_time","timestamp","datetime","sent_time","date_time"])),
                  first_value(row,["direction","sms_direction","type"]),
                  first_value(row,["message_type","service_type","sms_type"]),
                  first_value(row,["delivery_status","status"]),
                  first_value(row,["imei","device_imei"]), first_value(row,["imsi","subscriber_imsi"]),
                  first_value(row,["cell_id","cellid","cgi","eci"]), json.dumps(row,ensure_ascii=False)))
            elif dataset=="subscriber":
                ident=first_value(row,["id_number","identity_number","sa_id","id"])
                num=first_value(row,["msisdn","mobile_number","phone","phone_number","number"])
                check=validate_sa_id(ident) if ident else None
                con.execute("""INSERT INTO subscriber_records(
                  case_id,import_id,provider,source_row,id_number,id_valid,msisdn_raw,msisdn_norm,
                  subscriber_name,activation_date,status,sim_serial,imsi,raw_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(
                  case_id,import_id,provider,row_no,
                  re.sub(r"\D","",ident) if ident else None,
                  1 if check and check["valid"] else 0,
                  num,normalize_phone(num),
                  first_value(row,["subscriber_name","name","full_name","customer_name"]),
                  normalize_time(first_value(row,["activation_date","registered_date","start_date"])),
                  first_value(row,["status","subscriber_status","line_status"]),
                  first_value(row,["sim_serial","iccid","sim"]),
                  first_value(row,["imsi","subscriber_imsi"]),json.dumps(row,ensure_ascii=False)))
            else:
                raise ValueError("Unsupported dataset.")
            count += 1
    con.execute("UPDATE imports SET row_count=? WHERE id=?",(count,import_id))
    con.commit()
    return count,digest,import_id

@app.route("/login",methods=["GET","POST"])
def login():
    con = db()
    user_count = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if user_count == 0:
        return render_page("Configuration required","""
        <div class="card">
          <h2>Create the bootstrap administrator</h2>
          <p>No local users exist. Set <code>PREDITA_ADMIN_PASSWORD</code>, restart Predita once, then sign in as the configured bootstrap admin.</p>
        </div>""")

    if request.method=="POST":
        check_csrf()
        username=request.form.get("username","").strip()
        pw=request.form.get("password","")
        row=con.execute(
            "SELECT username,password_hash,role,active FROM users WHERE username=?",
            (username,)
        ).fetchone()
        if row and row["active"] and check_password_hash(row["password_hash"], pw):
            session.clear()
            session.permanent=True
            session["user"]=row["username"]
            session["role"]=row["role"]
            session["csrf"]=secrets.token_urlsafe(24)
            con.execute(
                "UPDATE users SET last_login_at=? WHERE username=?",
                (now_iso(), row["username"])
            )
            con.commit()
            audit("login")
            return redirect(url_for("home"))
        flash("Invalid credentials or inactive account.","error")

    return render_page("Sign in","""
      <div class="card" style="max-width:420px;margin:50px auto">
        <h2>Predita sign in</h2>
        <form method="post">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <label>Username</label><input name="username" autocomplete="username" required>
          <label>Password</label><input name="password" type="password" autocomplete="current-password" required>
          <div style="margin-top:12px"><button>Sign in</button></div>
        </form>
      </div>""")

@app.route("/logout")
@require_login
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@require_login
def home():
    con=db()
    cases=con.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    return render_page("Cases","""
    <div class="grid">
      {% if can('create_case') %}
      <div class="card">
        <h2>Create case</h2>
        <form method="post" action="{{ url_for('new_case') }}">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <label>Case ID</label><input name="case_id" placeholder="CASE-001" required>
          <label>Title</label><input name="title" placeholder="Investigation title">
          <label>Authority / request reference</label><input name="authority_ref" required>
          <div style="margin-top:12px"><button>Create</button></div>
        </form>
      </div>
      {% endif %}
      {% if can('validate_id') %}
      <div class="card">
        <h2>Validate SA ID</h2>
        <form method="post" action="{{ url_for('validate_id') }}">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <label>ID number</label><input name="id_number" inputmode="numeric" required>
          <div style="margin-top:12px"><button class="secondary">Validate</button></div>
        </form>
      </div>
      {% endif %}
    </div>

    <div class="card">
      <h2>Cases</h2>
      <table>
      <tr><th>Case</th><th>Title</th><th>Authority</th><th>Created</th></tr>
      {% for c in cases %}
      <tr>
        <td><a href="{{ url_for('case_view',case_id=c['case_id']) }}">{{ c['case_id'] }}</a></td>
        <td>{{ c['title'] or '' }}</td><td>{{ c['authority_ref'] }}</td><td>{{ c['created_at'] }}</td>
      </tr>
      {% else %}<tr><td colspan="4">No cases yet.</td></tr>{% endfor %}
      </table>
    </div>
    """,cases=cases)

@app.post("/case/new")
@require_permission("create_case")
def new_case():
    check_csrf()
    case_id=request.form["case_id"].strip()
    title=request.form.get("title","").strip()
    authority=request.form["authority_ref"].strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{3,80}",case_id):
        flash("Use a simple case ID containing letters, numbers, dash, dot or colon.","error")
        return redirect(url_for("home"))
    con=db()
    try:
        con.execute("INSERT INTO cases(case_id,authority_ref,title,created_at,created_by) VALUES(?,?,?,?,?)",
                    (case_id,authority,title,now_iso(),session["user"]))
        con.commit()
        audit("case_create",case_id,authority)
        return redirect(url_for("case_view",case_id=case_id))
    except sqlite3.IntegrityError:
        flash("That case ID already exists.","error")
        return redirect(url_for("home"))

@app.post("/validate-id")
@require_permission("validate_id")
def validate_id():
    check_csrf()
    value=request.form.get("id_number","")
    result=validate_sa_id(value)
    audit("id_validate",detail=f"valid={result['valid']}")
    return render_page("ID validation","""
      <div class="card">
       <h2>SA ID validation</h2>
       <p><strong>Result:</strong> {{ 'Valid structure/checksum' if r.valid else 'Invalid structure/checksum' }}</p>
       <table>
        <tr><th>Normalized</th><td>{{ r.normalized }}</td></tr>
        <tr><th>Date component</th><td>{{ r.date_ok }}</td></tr>
        <tr><th>Luhn checksum</th><td>{{ r.luhn_ok }}</td></tr>
        <tr><th>Citizenship code meaning</th><td>{{ r.citizenship }}</td></tr>
        <tr><th>Gender sequence meaning</th><td>{{ r.gender }}</td></tr>
       </table>
       <p class="small">This validates the number's structure/checksum only. It does not verify a person's identity against a government database.</p>
      </div>""",r=result)

@app.route("/case/<case_id>")
@require_login
def case_view(case_id):
    case=require_case(case_id)
    con=db()
    imports=con.execute("SELECT * FROM imports WHERE case_id=? ORDER BY imported_at DESC",(case_id,)).fetchall()
    q=request.args.get("q","").strip()
    dataset=request.args.get("dataset","all")
    rows=[]
    if q and not can("search_case"):
        flash("Your role does not permit searching case records.", "error")
        q = ""
    if q:
        nq=normalize_phone(q)
        ident=re.sub(r"\D","",q)
        if dataset in ("all","calls"):
            rows += [dict(r)|{"dataset":"call"} for r in con.execute("""
              SELECT provider,event_time,a_number_norm AS a,b_number_norm AS b,direction,
                     duration_seconds AS extra,imei,imsi,cell_id
              FROM call_records
              WHERE case_id=? AND (a_number_norm=? OR b_number_norm=?)
              ORDER BY event_time DESC LIMIT 200
            """,(case_id,nq,nq)).fetchall()]
        if dataset in ("all","sms"):
            rows += [dict(r)|{"dataset":"sms"} for r in con.execute("""
              SELECT provider,event_time,a_number_norm AS a,b_number_norm AS b,direction,
                     delivery_status AS extra,imei,imsi,cell_id
              FROM sms_records
              WHERE case_id=? AND (a_number_norm=? OR b_number_norm=?)
              ORDER BY event_time DESC LIMIT 200
            """,(case_id,nq,nq)).fetchall()]
        if dataset in ("all","subscriber"):
            rows += [dict(r)|{"dataset":"subscriber"} for r in con.execute("""
              SELECT provider,activation_date AS event_time,msisdn_norm AS a,
                     id_number AS b,status AS direction,subscriber_name AS extra,
                     NULL AS imei,imsi,NULL AS cell_id
              FROM subscriber_records
              WHERE case_id=? AND (msisdn_norm=? OR id_number=?)
              ORDER BY id DESC LIMIT 200
            """,(case_id,nq,ident)).fetchall()]
        audit("case_search",case_id,f"dataset={dataset}; results={len(rows)}")

    receipts=con.execute("""
      SELECT id,dataset_type,provider,authority_ref,source_reference,original_filename,
             sha256,file_size,received_at,received_by,status,approved_at,approved_by,
             import_id,rejection_reason,notes
      FROM evidence_receipts
      WHERE case_id=? ORDER BY id DESC
    """,(case_id,)).fetchall()

    checks=con.execute("""
      SELECT provider,capability,msisdn_norm,checked_at,http_status,
             provider_transaction_id,result_status,result_json
      FROM provider_checks
      WHERE case_id=? ORDER BY id DESC LIMIT 30
    """,(case_id,)).fetchall()

    audits=con.execute("""
      SELECT event_time,username,action,detail FROM audit_events
      WHERE case_id=? ORDER BY id DESC LIMIT 30
    """,(case_id,)).fetchall()

    return render_page(f"Case {case_id}","""
    <div class="card">
      <h2>{{ case['case_id'] }}{% if case['title'] %} · {{ case['title'] }}{% endif %}</h2>
      <div class="small">Authority: {{ case['authority_ref'] }}</div>
    </div>

    {% if can('receive_evidence') %}
    <div class="card">
      <h3>Receive authorized evidence</h3>
      <p class="small">The original CSV is stored unchanged and hashed first. It is not searchable until an investigator explicitly approves the receipt for import.</p>
      <form method="post" enctype="multipart/form-data" action="{{ url_for('receive_evidence',case_id=case['case_id']) }}">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <div class="grid">
          <div><label>Dataset</label>
            <select name="dataset_type" required>
              <option value="calls">Call records</option>
              <option value="sms">SMS metadata</option>
              <option value="subscriber">Subscriber / RICA records</option>
            </select>
          </div>
          <div><label>Provider/source</label><input name="provider" placeholder="Vodacom / MTN / agency export" required></div>
          <div><label>Authority/reference</label><input name="authority_ref" value="{{ case['authority_ref'] }}" required></div>
          <div><label>Provider/transfer reference</label><input name="source_reference" placeholder="LEA request, secure-transfer or export ref"></div>
        </div>
        <label>Notes</label><input name="notes" placeholder="Optional provenance note; do not put passwords or access tokens here">
        <label>Original CSV evidence file</label><input type="file" name="file" accept=".csv,text/csv" required>
        <div style="margin-top:12px"><button>Receive and hash evidence</button></div>
      </form>
    </div>
    {% endif %}

    <div class="card">
      <h3>Evidence receipts</h3>
      <div style="overflow:auto">
      <table>
        <tr><th>ID</th><th>Status</th><th>Dataset</th><th>Provider</th><th>Source ref</th><th>File</th><th>Size</th><th>SHA-256</th><th>Received</th><th>Action</th></tr>
        {% for e in receipts %}
        <tr>
          <td>#{{ e['id'] }}</td>
          <td><span class="badge">{{ e['status'] }}</span></td>
          <td>{{ e['dataset_type'] }}</td><td>{{ e['provider'] }}</td>
          <td>{{ e['source_reference'] or '' }}</td><td>{{ e['original_filename'] }}</td>
          <td>{{ e['file_size'] }}</td><td class="small">{{ e['sha256'] }}</td>
          <td>{{ e['received_at'] }}<br><span class="small">{{ e['received_by'] }}</span></td>
          <td>
          {% if e['status'] == 'received' and can('approve_evidence') %}
            <form method="post" action="{{ url_for('approve_evidence',case_id=case['case_id'],receipt_id=e['id']) }}" style="margin-bottom:6px">
              <input type="hidden" name="csrf" value="{{ csrf_token() }}">
              <button>Verify hash + import</button>
            </form>
            <form method="post" action="{{ url_for('reject_evidence',case_id=case['case_id'],receipt_id=e['id']) }}">
              <input type="hidden" name="csrf" value="{{ csrf_token() }}">
              <input name="reason" placeholder="Rejection reason" required>
              <button class="secondary" style="margin-top:5px">Reject</button>
            </form>
          {% elif e['status'] == 'imported' %}
            Import #{{ e['import_id'] }}
          {% elif e['status'] == 'rejected' %}
            <span class="small">{{ e['rejection_reason'] or '' }}</span>
          {% endif %}
          </td>
        </tr>
        {% else %}<tr><td colspan="10">No evidence received for this case.</td></tr>{% endfor %}
      </table></div>
    </div>

    {% if can('search_case') %}
    <div class="card">
      <h3>Search this case</h3>
      <form method="get">
        <div class="grid">
          <div><label>Mobile number or ID number</label><input name="q" value="{{ q }}" required></div>
          <div><label>Dataset</label>
            <select name="dataset">
              {% for v,n in [('all','All'),('calls','Calls'),('sms','SMS'),('subscriber','Subscriber')] %}
              <option value="{{ v }}" {{ 'selected' if dataset==v else '' }}>{{ n }}</option>
              {% endfor %}
            </select>
          </div>
        </div>
        <div style="margin-top:12px"><button class="secondary">Search</button></div>
      </form>
    </div>
    {% endif %}

    {% if q %}
    <div class="card">
      <h3>Search results <span class="badge">{{ rows|length }}</span></h3>
      <div style="overflow:auto">
      <table>
        <tr><th>Type</th><th>Provider</th><th>Time/activation</th><th>A/number</th><th>B/ID</th><th>Direction/status</th><th>Extra</th><th>IMEI</th><th>IMSI</th><th>Cell</th></tr>
        {% for r in rows %}
        <tr>
          <td>{{ r.dataset }}</td><td>{{ r.provider }}</td><td>{{ r.event_time or '' }}</td>
          <td>{{ r.a or '' }}</td><td>{{ r.b or '' }}</td><td>{{ r.direction or '' }}</td>
          <td>{{ r.extra or '' }}</td><td>{{ r.imei or '' }}</td><td>{{ r.imsi or '' }}</td><td>{{ r.cell_id or '' }}</td>
        </tr>
        {% else %}<tr><td colspan="10">No matching authorized records in this case.</td></tr>{% endfor %}
      </table></div>
    </div>
    {% endif %}

    {% if can('provider_check') %}
    <div class="card">
      <h3>Approved network checks</h3>
      <p class="small">MTN SIM-swap date uses the server-side MTN Mobile Customer Information API only when you have approved credentials and explicitly enable it.</p>
      <form method="post" action="{{ url_for('network_check',case_id=case['case_id']) }}">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <div class="grid">
          <div><label>Provider capability</label>
            <select name="capability"><option value="mtn_sim_swap">MTN · Last SIM-swap date</option></select>
          </div>
          <div><label>Mobile number</label><input name="number" placeholder="+27821234567" required></div>
        </div>
        <div style="margin-top:12px"><button class="secondary">Run approved check</button></div>
      </form>

      <div style="overflow:auto;margin-top:14px">
      <table><tr><th>Checked</th><th>Provider</th><th>Capability</th><th>Number</th><th>Status</th><th>HTTP</th><th>Transaction</th></tr>
      {% for c in checks %}
      <tr><td>{{ c['checked_at'] }}</td><td>{{ c['provider'] }}</td><td>{{ c['capability'] }}</td>
          <td>{{ c['msisdn_norm'] }}</td><td>{{ c['result_status'] }}</td>
          <td>{{ c['http_status'] if c['http_status'] is not none else '' }}</td>
          <td>{{ c['provider_transaction_id'] or '' }}</td></tr>
      {% else %}<tr><td colspan="7">No provider checks run for this case.</td></tr>{% endfor %}
      </table></div>
    </div>
    {% endif %}

    <div class="card">
      <h3>Evidence imports</h3>
      <table><tr><th>Type</th><th>Provider</th><th>File</th><th>Rows</th><th>SHA-256</th><th>Imported</th></tr>
      {% for i in imports %}
      <tr><td>{{ i['dataset_type'] }}</td><td>{{ i['provider'] }}</td><td>{{ i['source_file'] }}</td>
          <td>{{ i['row_count'] }}</td><td class="small">{{ i['sha256'] }}</td><td>{{ i['imported_at'] }}</td></tr>
      {% else %}<tr><td colspan="6">No evidence imported.</td></tr>{% endfor %}
      </table>
    </div>

    <div class="card">
      <h3>Recent audit events</h3>
      <table><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr>
      {% for a in audits %}
      <tr><td>{{ a['event_time'] }}</td><td>{{ a['username'] }}</td><td>{{ a['action'] }}</td><td>{{ a['detail'] or '' }}</td></tr>
      {% else %}<tr><td colspan="4">No events yet.</td></tr>{% endfor %}
      </table>
    </div>
    """,case=case,imports=imports,receipts=receipts,rows=rows,q=q,dataset=dataset,checks=checks,audits=audits)

@app.post("/case/<case_id>/evidence/receive")
@require_permission("receive_evidence")
def receive_evidence(case_id):
    check_csrf()
    require_case(case_id)

    dataset = request.form.get("dataset_type", "").strip()
    provider = request.form.get("provider", "").strip()
    authority = request.form.get("authority_ref", "").strip()
    source_reference = request.form.get("source_reference", "").strip()
    notes = request.form.get("notes", "").strip()
    f = request.files.get("file")

    if dataset not in {"calls", "sms", "subscriber"}:
        abort(400, "Unsupported evidence dataset.")
    if not provider or not authority:
        flash("Provider/source and authority reference are required.", "error")
        return redirect(url_for("case_view", case_id=case_id))
    if not f or not f.filename:
        flash("Choose an evidence CSV file.", "error")
        return redirect(url_for("case_view", case_id=case_id))
    if not f.filename.lower().endswith(".csv"):
        flash("This intake currently accepts CSV evidence only.", "error")
        return redirect(url_for("case_view", case_id=case_id))

    original_name = f.filename
    safe = secure_filename(original_name) or "evidence.csv"
    stored_name = f"{secrets.token_hex(16)}_{safe}"
    dest = UPLOAD_DIR / stored_name
    f.save(dest)

    digest = file_sha(dest)
    size = dest.stat().st_size

    con = db()
    try:
        cur = con.execute("""
          INSERT INTO evidence_receipts(
            case_id,dataset_type,provider,authority_ref,source_reference,
            original_filename,stored_path,sha256,file_size,received_at,received_by,
            status,notes
          ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
          case_id,dataset,provider,authority,source_reference or None,
          original_name,str(dest),digest,size,now_iso(),session["user"],
          "received",notes or None
        ))
        receipt_id = cur.lastrowid
        con.commit()
    except sqlite3.IntegrityError:
        dest.unlink(missing_ok=True)
        flash("An identical evidence file has already been received for this case.", "error")
        return redirect(url_for("case_view", case_id=case_id))

    audit(
        "evidence_received",
        case_id,
        f"receipt={receipt_id}; dataset={dataset}; provider={provider}; sha256={digest}; size={size}"
    )
    flash(f"Evidence receipt #{receipt_id} stored unchanged and hashed. Review it before import.")
    return redirect(url_for("case_view", case_id=case_id))


@app.post("/case/<case_id>/evidence/<int:receipt_id>/approve")
@require_permission("approve_evidence")
def approve_evidence(case_id, receipt_id):
    check_csrf()
    require_case(case_id)
    con = db()
    receipt = con.execute("""
      SELECT * FROM evidence_receipts WHERE id=? AND case_id=?
    """, (receipt_id, case_id)).fetchone()
    if not receipt:
        abort(404)
    if receipt["status"] != "received":
        flash("That evidence receipt is no longer awaiting review.", "error")
        return redirect(url_for("case_view", case_id=case_id))

    if receipt["received_by"] == session["user"] and not ALLOW_SELF_APPROVAL:
        flash("Separation of duties: the user who received this evidence cannot approve/import it.", "error")
        audit("self_approval_blocked", case_id, f"receipt={receipt_id}")
        return redirect(url_for("case_view", case_id=case_id))

    path = Path(receipt["stored_path"])
    if not path.is_file():
        flash("The preserved evidence file is missing from storage.", "error")
        audit("evidence_integrity_failure", case_id, f"receipt={receipt_id}; missing_file")
        return redirect(url_for("case_view", case_id=case_id))

    current_hash = file_sha(path)
    if not hmac.compare_digest(current_hash, receipt["sha256"]):
        flash("Evidence integrity check failed: SHA-256 no longer matches the received file.", "error")
        audit(
            "evidence_integrity_failure",
            case_id,
            f"receipt={receipt_id}; expected={receipt['sha256']}; actual={current_hash}"
        )
        return redirect(url_for("case_view", case_id=case_id))

    try:
        count, digest, import_id = import_csv(
            case_id,
            receipt["dataset_type"],
            receipt["provider"],
            receipt["authority_ref"],
            path
        )
    except Exception as exc:
        flash(f"Evidence passed hash verification but import failed: {exc}", "error")
        audit("evidence_import_failed", case_id, f"receipt={receipt_id}; error={exc}")
        return redirect(url_for("case_view", case_id=case_id))

    con = db()
    con.execute("""
      UPDATE evidence_receipts
      SET status='imported', approved_at=?, approved_by=?, import_id=?
      WHERE id=? AND case_id=?
    """, (now_iso(), session["user"], import_id, receipt_id, case_id))
    con.commit()

    audit(
        "evidence_approved_imported",
        case_id,
        f"receipt={receipt_id}; import={import_id}; rows={count}; sha256={digest}"
    )
    flash(f"Evidence receipt #{receipt_id} verified and imported: {count} rows.")
    return redirect(url_for("case_view", case_id=case_id))


@app.post("/case/<case_id>/evidence/<int:receipt_id>/reject")
@require_permission("approve_evidence")
def reject_evidence(case_id, receipt_id):
    check_csrf()
    require_case(case_id)
    reason = request.form.get("reason", "").strip()
    if not reason:
        flash("A rejection reason is required.", "error")
        return redirect(url_for("case_view", case_id=case_id))

    con = db()
    receipt = con.execute("""
      SELECT status FROM evidence_receipts WHERE id=? AND case_id=?
    """, (receipt_id, case_id)).fetchone()
    if not receipt:
        abort(404)
    if receipt["status"] != "received":
        flash("Only unreviewed evidence can be rejected.", "error")
        return redirect(url_for("case_view", case_id=case_id))

    con.execute("""
      UPDATE evidence_receipts
      SET status='rejected', rejection_reason=?, approved_at=?, approved_by=?
      WHERE id=? AND case_id=?
    """, (reason, now_iso(), session["user"], receipt_id, case_id))
    con.commit()

    audit("evidence_rejected", case_id, f"receipt={receipt_id}; reason={reason}")
    flash(f"Evidence receipt #{receipt_id} rejected. The original preserved file was not deleted.")
    return redirect(url_for("case_view", case_id=case_id))


@app.post("/case/<case_id>/network-check")
@require_permission("provider_check")
def network_check(case_id):
    check_csrf()
    require_case(case_id)
    capability = request.form.get("capability", "")
    number = request.form.get("number", "").strip()
    number_norm = normalize_phone(number)

    if capability != "mtn_sim_swap":
        abort(400, "Unsupported provider capability.")

    result = mtn_sim_swap_date(number)
    con = db()
    payload = result.get("payload")
    con.execute("""
      INSERT INTO provider_checks(
        case_id,provider,capability,msisdn_norm,checked_at,requested_by,
        http_status,provider_transaction_id,result_status,result_json
      ) VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (
        case_id, "MTN", "sim_swap_date", number_norm or number, now_iso(), session["user"],
        result.get("http_status"), result.get("provider_transaction_id"),
        result.get("status","unknown"),
        json.dumps(payload, ensure_ascii=False) if payload is not None else None
    ))
    con.commit()

    audit("provider_check", case_id, f"MTN sim_swap_date; status={result.get('status')}")
    if result.get("ok"):
        swap_date = result.get("last_sim_swap_date")
        flash(f"MTN check completed. Last SIM-swap date: {swap_date or 'unknown/not determined'}.")
    else:
        flash(result.get("message") or f"MTN check status: {result.get('status')}", "error")
    return redirect(url_for("case_view", case_id=case_id))

@app.route("/admin/users", methods=["GET"])
@require_permission("manage_users")
def users_admin():
    con = db()
    users = con.execute("""
      SELECT username,role,active,created_at,created_by,last_login_at
      FROM users ORDER BY username
    """).fetchall()
    return render_page("Users","""
    <div class="card">
      <h2>Predita users</h2>
      <p class="small">Use distinct accounts for evidence intake and approval. Production deployments should replace local passwords with agency SSO/MFA.</p>
      <table>
        <tr><th>User</th><th>Role</th><th>Active</th><th>Created</th><th>Last login</th></tr>
        {% for u in users %}
        <tr><td>{{ u['username'] }}</td><td>{{ u['role'] }}</td><td>{{ 'yes' if u['active'] else 'no' }}</td>
            <td>{{ u['created_at'] }}</td><td>{{ u['last_login_at'] or '' }}</td></tr>
        {% endfor %}
      </table>
    </div>
    <div class="card">
      <h3>Create user</h3>
      <form method="post" action="{{ url_for('create_user') }}">
        <input type="hidden" name="csrf" value="{{ csrf_token() }}">
        <label>Username</label><input name="username" required>
        <label>Role</label>
        <select name="role">
          <option value="intake">Intake</option>
          <option value="investigator">Investigator</option>
          <option value="approver">Approver</option>
          <option value="admin">Admin</option>
        </select>
        <label>Temporary password</label><input type="password" name="password" minlength="12" required>
        <div style="margin-top:12px"><button>Create user</button></div>
      </form>
    </div>
    """, users=users)


@app.post("/admin/users/create")
@require_permission("manage_users")
def create_user():
    check_csrf()
    username = request.form.get("username","").strip()
    role = request.form.get("role","").strip()
    password = request.form.get("password","")

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        flash("Username must be 3–64 characters using letters, numbers, dot, dash or underscore.", "error")
        return redirect(url_for("users_admin"))
    if role not in ROLE_PERMISSIONS:
        flash("Invalid role.", "error")
        return redirect(url_for("users_admin"))
    if len(password) < 12:
        flash("Password must be at least 12 characters.", "error")
        return redirect(url_for("users_admin"))

    con = db()
    try:
        con.execute("""
          INSERT INTO users(username,password_hash,role,active,created_at,created_by)
          VALUES(?,?,?,?,?,?)
        """, (
            username, generate_password_hash(password), role, 1,
            now_iso(), session["user"]
        ))
        con.commit()
    except sqlite3.IntegrityError:
        flash("That username already exists.", "error")
        return redirect(url_for("users_admin"))

    audit("user_created", detail=f"username={username}; role={role}")
    flash(f"Created {role} user {username}.")
    return redirect(url_for("users_admin"))


@app.post("/case/<case_id>/import/<dataset>")
@require_login
def import_data(case_id,dataset):
    abort(404)

if __name__ == "__main__":
    host=os.environ.get("PREDITA_HOST","127.0.0.1")
    port=int(os.environ.get("PORT","5000"))
    app.run(host=host,port=port,debug=False)
