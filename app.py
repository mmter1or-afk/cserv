#!/usr/bin/env python3
import os, sqlite3, time, bcrypt, secrets, functools, re, logging
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_file, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# Настройка постоянного секретного ключа
SECRET_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    new_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(new_key)
    app.secret_key = new_key

ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', secrets.token_hex(12))

# Прокси-фикс для корректных URL и схем за nginx
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Настройки сессий для работы через HTTPS
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

AVATAR_FOLDER = os.path.join('static', 'avatars')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(AVATAR_FOLDER, exist_ok=True)
app.config['AVATAR_FOLDER'] = AVATAR_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                hwid TEXT DEFAULT NULL,
                subscription_expiry INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY,
                duration_days INTEGER NOT NULL,
                created_by TEXT DEFAULT 'system',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                used_by INTEGER DEFAULT NULL REFERENCES users(id),
                redeemed_at INTEGER DEFAULT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')

def migrate_db():
    conn = get_db()
    cur = conn.cursor()
    cols = [col[1] for col in cur.execute('PRAGMA table_info(users)').fetchall()]
    if 'display_name' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN display_name TEXT UNIQUE DEFAULT NULL')
    if 'avatar_path' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT NULL')
    conn.commit()
    conn.close()

init_db()
migrate_db()

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def parse_loose_json(raw_bytes):
    try:
        text = raw_bytes.decode('utf-8', errors='ignore').strip()
    except:
        return None
    if not (text.startswith('{') and text.endswith('}')):
        return None
    content = text[1:-1]
    pairs = re.split(r',(?![^{]*\})', content)
    data = {}
    for pair in pairs:
        if ':' not in pair: continue
        k, v = pair.split(':', 1)
        k = k.strip().strip('"\'')
        v = v.strip().strip('"\'')
        if v.lower() == 'true': v = True
        elif v.lower() == 'false': v = False
        elif v.isdigit(): v = int(v)
        data[k] = v
    return data if data else None

# API для лоадера
@app.route('/auth', methods=['POST'])
def auth():
    raw_body = request.get_data()
    try:
        data = request.json
    except:
        data = None
    if data is None:
        data = parse_loose_json(raw_body)
    if data is None:
        return jsonify({'error': 'Invalid JSON'}), 400

    username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')
    check_only = data.get('check_only', False)
    file = data.get('file', 'dll')

    if not username or not password or not hwid:
        return jsonify({'error': 'Missing fields'}), 400

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401
    if user['subscription_expiry'] < int(time.time()):
        return jsonify({'error': 'Subscription expired'}), 403

    if user['hwid'] is None:
        db.execute('UPDATE users SET hwid = ? WHERE id = ?', (hwid, user['id']))
        db.commit()
    elif user['hwid'] != hwid:
        return jsonify({'error': 'HWID mismatch'}), 403

    if check_only:
        return jsonify({'success': True})

    if file == 'dll':
        dll_path = os.path.join('cheat/internal.dll')
        if not os.path.exists(dll_path):
            return jsonify({'error': 'DLL not found'}), 500
        return send_file(dll_path, as_attachment=True, download_name='internal.dll', mimetype='application/octet-stream')
    elif file == 'exe':
        exe_path = os.path.join('cheat/Overlay.exe')
        if not os.path.exists(exe_path):
            return jsonify({'error': 'Overlay.exe not found'}), 500
        return send_file(exe_path, as_attachment=True, download_name='Overlay.exe', mimetype='application/octet-stream')
    return jsonify({'error': 'Invalid file type'}), 400

# Веб-страницы
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        key = data.get('key')
        if not username or not password or not key:
            return jsonify({'error': 'Missing fields'}), 400
        db = get_db()
        key_data = db.execute('SELECT * FROM keys WHERE key = ? AND used_by IS NULL', (key,)).fetchone()
        if not key_data:
            return jsonify({'error': 'Invalid or already used key'}), 400
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            return jsonify({'error': 'User already exists'}), 400
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        expiry = int(time.time()) + key_data['duration_days'] * 86400
        db.execute('INSERT INTO users (username, password_hash, subscription_expiry, created_at) VALUES (?,?,?,?)',
                   (username, password_hash, expiry, int(time.time())))
        db.execute('UPDATE keys SET used_by = (SELECT id FROM users WHERE username = ?), redeemed_at = ? WHERE key = ?',
                   (username, int(time.time()), key))
        db.commit()
        if request.is_json:
            return jsonify({'success': True})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session['user_id'] = user['id']
            return redirect(url_for('panel'))
        return render_template('login.html', error='Неверный логин или пароль')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
@login_required
def panel():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    expiry = user['subscription_expiry']
    days_left = max(0, (expiry - int(time.time())) // 86400)
    expiry_str = datetime.utcfromtimestamp(expiry).strftime('%d.%m.%Y')
    hwid = user['hwid'] or 'Не привязан'
    display_name = user['display_name'] or user['username']
    avatar = user['avatar_path'] or 'avatars/default.png'
    return render_template('panel.html', user=user, display_name=display_name,
                           hwid=hwid, expiry_str=expiry_str, days_left=days_left, avatar=avatar)

@app.route('/panel/update', methods=['POST'])
@login_required
def panel_update():
    db = get_db()
    user_id = session['user_id']
    new_display = request.form.get('display_name', '').strip()
    if new_display:
        exists = db.execute('SELECT id FROM users WHERE display_name = ? AND id != ?',
                           (new_display, user_id)).fetchone()
        if exists:
            return jsonify({'error': 'Это имя уже занято'}), 400
        db.execute('UPDATE users SET display_name = ? WHERE id = ?', (new_display, user_id))
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename != '':
            if not file.filename.lower().endswith(tuple(ALLOWED_EXTENSIONS)):
                return jsonify({'error': 'Недопустимый формат файла'}), 400
            filename = secure_filename(f"user_{user_id}.png")
            filepath = os.path.join(app.config['AVATAR_FOLDER'], filename)
            file.save(filepath)
            avatar_path = f"avatars/{filename}"
            db.execute('UPDATE users SET avatar_path = ? WHERE id = ?', (avatar_path, user_id))
    db.commit()
    return redirect(url_for('panel'))

# Чат API
@app.route('/api/chat/send', methods=['POST'])
@login_required
def chat_send():
    data = request.get_json()
    msg = data.get('message', '').strip()
    if not msg:
        return jsonify({'error': 'Пустое сообщение'}), 400
    db = get_db()
    db.execute('INSERT INTO chat_messages (user_id, message) VALUES (?, ?)',
               (session['user_id'], msg))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/chat/messages')
@login_required
def chat_messages():
    db = get_db()
    messages = db.execute('''
        SELECT cm.id, cm.message, cm.created_at,
               u.display_name, u.username, u.avatar_path
        FROM chat_messages cm
        JOIN users u ON cm.user_id = u.id
        ORDER BY cm.id DESC LIMIT 50
    ''').fetchall()
    result = []
    for m in reversed(messages):
        result.append({
            'id': m['id'],
            'message': m['message'],
            'created_at': datetime.utcfromtimestamp(m['created_at']).strftime('%H:%M'),
            'display_name': m['display_name'] or m['username'],
            'avatar': m['avatar_path'] or 'avatars/default.png'
        })
    return jsonify(result)

# Админка
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USER and request.form.get('password') == ADMIN_PASS:
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        return render_template('admin/login.html', error='Неверные данные')
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/panel')
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    keys = db.execute('SELECT * FROM keys').fetchall()
    now = int(time.time())
    return render_template('admin/panel.html', users=users, keys=keys, now=now)

@app.route('/admin/generate', methods=['GET', 'POST'])
@admin_required
def admin_generate():
    if request.method == 'POST':
        days = int(request.form['days'])
        key = secrets.token_hex(8).upper()
        db = get_db()
        db.execute('INSERT INTO keys (key, duration_days, created_by) VALUES (?,?,?)', (key, days, 'admin'))
        db.commit()
        return render_template('admin/generate.html', key=key, days=days)
    return render_template('admin/generate.html', key=None)

@app.route('/avatars/<path:filename>')
def avatars(filename):
    return send_from_directory('static/avatars', filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
