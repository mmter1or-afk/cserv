#!/usr/bin/env python3
"""Production-oriented Flask application for the Hades access portal."""

from __future__ import annotations

import functools
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("DATABASE_URL", BASE_DIR / "database.db"))
SECRET_KEY_FILE = BASE_DIR / "secret_key.txt"
AVATAR_FOLDER = BASE_DIR / "static" / "avatars"
CHAT_MESSAGE_LIMIT = 50
MAX_CHAT_LENGTH = 800
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
DISPLAY_NAME_RE = re.compile(r"^[\w .\-А-Яа-яЁё]{2,40}$", re.UNICODE)
ALLOWED_AVATAR_MIMES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
}

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(key, encoding="utf-8")
    try:
        SECRET_KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.secret_key = _load_secret_key()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config.update(
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # CSRF tokens are stored in Flask's signed session cookie. A Secure
    # cookie is correct behind HTTPS, but it is not sent by browsers over
    # plain HTTP; default to local/proxy-safe behavior and let production
    # deployments opt in with SESSION_COOKIE_SECURE=true.
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", False),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS")
AVATAR_FOLDER.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.executescript("""
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                hwid TEXT DEFAULT NULL,
                subscription_expiry INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                display_name TEXT DEFAULT NULL,
                avatar_path TEXT DEFAULT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_display_name
                ON users(display_name) WHERE display_name IS NOT NULL;
            CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY,
                duration_days INTEGER NOT NULL CHECK(duration_days BETWEEN 1 AND 3650),
                created_by TEXT DEFAULT 'system',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                used_by INTEGER DEFAULT NULL REFERENCES users(id),
                redeemed_at INTEGER DEFAULT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                message TEXT NOT NULL CHECK(length(message) <= 800),
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            """)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "display_name" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT NULL")
        if "avatar_path" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT NULL")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name) WHERE display_name IS NOT NULL"
        )


init_db()


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def reset_session(**values: Any) -> None:
    """Start a fresh browser session while immediately issuing a CSRF token."""
    session.clear()
    session.permanent = True
    session.update(values)
    session["csrf_token"] = secrets.token_urlsafe(32)


app.jinja_env.globals["csrf_token"] = csrf_token


@app.template_filter("datetime")
def datetime_filter(value: int, fmt: str = "%d.%m.%Y") -> str:
    return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(fmt)


@app.before_request
def protect_state_changes() -> None:
    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and request.endpoint != "auth"
    ):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not sent or not secrets.compare_digest(sent, session.get("csrf_token", "")):
            abort(400, "Invalid CSRF token")


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
    )
    return response


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)

    return decorated


def json_payload() -> dict[str, Any] | None:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ""))


def validate_password(password: str) -> bool:
    return 8 <= len(password or "") <= 128


def validate_avatar(file_storage) -> str | None:
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    for magic, ext in ALLOWED_AVATAR_MIMES.items():
        if head.startswith(magic):
            return ext
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/auth", methods=["POST"])
def auth():
    data = json_payload()
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    hwid = str(data.get("hwid", ""))
    check_only = bool(data.get("check_only", False))
    file_key = str(data.get("file", "dll"))
    if not (validate_username(username) and password and 8 <= len(hwid) <= 256):
        return jsonify({"error": "Missing or invalid fields"}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not bcrypt.checkpw(
        password.encode(), user["password_hash"].encode()
    ):
        return jsonify({"error": "Invalid credentials"}), 401
    if user["subscription_expiry"] < int(time.time()):
        return jsonify({"error": "Subscription expired"}), 403
    if user["hwid"] is None:
        db.execute("UPDATE users SET hwid = ? WHERE id = ?", (hwid, user["id"]))
        db.commit()
    elif user["hwid"] != hwid:
        return jsonify({"error": "HWID mismatch"}), 403
    if check_only:
        return jsonify({"success": True})
    artifacts = {
        "dll": (BASE_DIR / "cheat" / "internal.dll", "internal.dll"),
        "exe": (BASE_DIR / "cheat" / "Overlay.exe", "Overlay.exe"),
    }
    artifact = artifacts.get(file_key)
    if not artifact:
        return jsonify({"error": "Invalid file type"}), 400
    path, download_name = artifact
    if not path.is_file():
        return jsonify({"error": "File not found"}), 404
    return send_file(
        path,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream",
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = json_payload() if request.is_json else request.form
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        access_key = str(data.get("key", "")).strip().upper()
        if not validate_username(username):
            return (
                jsonify(
                    {
                        "error": "Use 3–32 letters, numbers, dots, dashes or underscores for the login."
                    }
                ),
                400,
            )
        if not validate_password(password):
            return jsonify({"error": "Password must be 8–128 characters."}), 400
        db = get_db()
        key_data = db.execute(
            "SELECT * FROM keys WHERE key = ? AND used_by IS NULL", (access_key,)
        ).fetchone()
        if not key_data:
            return jsonify({"error": "Invalid or already used key"}), 400
        if db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone():
            return jsonify({"error": "User already exists"}), 400
        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt(rounds=12)
        ).decode()
        now = int(time.time())
        expiry = now + int(key_data["duration_days"]) * 86400
        cur = db.execute(
            "INSERT INTO users (username, password_hash, subscription_expiry, created_at) VALUES (?,?,?,?)",
            (username, password_hash, expiry, now),
        )
        db.execute(
            "UPDATE keys SET used_by = ?, redeemed_at = ? WHERE key = ?",
            (cur.lastrowid, now, access_key),
        )
        db.commit()
        return (
            jsonify({"success": True})
            if request.is_json
            else redirect(url_for("login"))
        )
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            reset_session(user_id=user["id"])
            return redirect(url_for("panel"))
        return render_template("login.html", error="Неверный логин или пароль")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/chat")
@login_required
def chat_page():
    return render_template("chat.html")


@app.route("/panel")
@login_required
def panel():
    user = (
        get_db()
        .execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        .fetchone()
    )
    if not user:
        session.clear()
        return redirect(url_for("login"))
    expiry = int(user["subscription_expiry"])
    return render_template(
        "panel.html",
        user=user,
        display_name=user["display_name"] or user["username"],
        hwid=user["hwid"] or "Не привязан",
        expiry_str=datetime_filter(expiry),
        days_left=max(0, (expiry - int(time.time())) // 86400),
        avatar=user["avatar_path"] or "avatars/default.png",
    )


@app.route("/panel/update", methods=["POST"])
@login_required
def panel_update():
    db = get_db()
    user_id = session["user_id"]
    new_display = request.form.get("display_name", "").strip()
    if new_display:
        if not DISPLAY_NAME_RE.fullmatch(new_display):
            return jsonify({"error": "Display name must be 2–40 safe characters."}), 400
        exists = db.execute(
            "SELECT id FROM users WHERE display_name = ? AND id != ?",
            (new_display, user_id),
        ).fetchone()
        if exists:
            return jsonify({"error": "Это имя уже занято"}), 400
        db.execute(
            "UPDATE users SET display_name = ? WHERE id = ?", (new_display, user_id)
        )
    file = request.files.get("avatar")
    if file and file.filename:
        ext = validate_avatar(file)
        if not ext:
            return jsonify({"error": "Недопустимый формат файла"}), 400
        filename = secure_filename(f"user_{user_id}.{ext}")
        file.save(AVATAR_FOLDER / filename)
        db.execute(
            "UPDATE users SET avatar_path = ? WHERE id = ?",
            (f"avatars/{filename}", user_id),
        )
    db.commit()
    return redirect(url_for("panel"))


@app.route("/api/chat/send", methods=["POST"])
@login_required
def chat_send():
    data = json_payload()
    msg = str((data or {}).get("message", "")).strip()
    if not msg or len(msg) > MAX_CHAT_LENGTH:
        return jsonify({"error": "Message must be 1–800 characters."}), 400
    get_db().execute(
        "INSERT INTO chat_messages (user_id, message) VALUES (?, ?)",
        (session["user_id"], msg),
    )
    get_db().commit()
    return jsonify({"success": True})


@app.route("/api/chat/messages")
@login_required
def chat_messages():
    messages = (
        get_db()
        .execute(
            """
        SELECT cm.id, cm.message, cm.created_at, u.display_name, u.username, u.avatar_path
        FROM chat_messages cm JOIN users u ON cm.user_id = u.id
        ORDER BY cm.id DESC LIMIT ?
        """,
            (CHAT_MESSAGE_LIMIT,),
        )
        .fetchall()
    )
    return jsonify(
        [
            {
                "id": m["id"],
                "message": m["message"],
                "created_at": datetime_filter(m["created_at"], "%H:%M"),
                "display_name": m["display_name"] or m["username"],
                "avatar": m["avatar_path"] or "avatars/default.png",
            }
            for m in reversed(messages)
        ]
    )


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (
            ADMIN_PASS
            and request.form.get("username") == ADMIN_USER
            and secrets.compare_digest(request.form.get("password", ""), ADMIN_PASS)
        ):
            reset_session(admin=True)
            return redirect(url_for("admin_panel"))
        return render_template("admin/login.html", error="Неверные данные")
    return render_template("admin/login.html", admin_configured=bool(ADMIN_PASS))


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/panel")
@admin_required
def admin_panel():
    db = get_db()
    return render_template(
        "admin/panel.html",
        users=db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall(),
        keys=db.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall(),
        now=int(time.time()),
    )


@app.route("/admin/generate", methods=["GET", "POST"])
@admin_required
def admin_generate():
    if request.method == "POST":
        try:
            days = int(request.form.get("days", ""))
        except ValueError:
            days = 0
        if not 1 <= days <= 3650:
            return render_template(
                "admin/generate.html", key=None, error="Укажите срок от 1 до 3650 дней."
            )
        key = secrets.token_urlsafe(18).replace("-", "A").replace("_", "B").upper()
        get_db().execute(
            "INSERT INTO keys (key, duration_days, created_by) VALUES (?,?,?)",
            (key, days, ADMIN_USER),
        )
        get_db().commit()
        return render_template("admin/generate.html", key=key, days=days)
    return render_template("admin/generate.html", key=None)


@app.route("/avatars/<path:filename>")
def avatars(filename: str):
    return send_from_directory(AVATAR_FOLDER, secure_filename(filename))


@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\nDisallow: /admin\nDisallow: /panel\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.route("/sitemap.xml")
def sitemap():
    return (
        render_template("sitemap.xml", base_url=request.url_root.rstrip("/")),
        200,
        {"Content-Type": "application/xml; charset=utf-8"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
