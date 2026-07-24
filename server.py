#!/usr/bin/env python3
import os, sqlite3, time, bcrypt, secrets, functools, json, re, logging
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, send_file
from datetime import datetime

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# УДАЛЯЕМ эти строки или комментируем:
# ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
# ADMIN_PASS = os.environ.get('ADMIN_PASS', secrets.token_hex(12))

BASE_CSS = '''
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
           background: #0f1117; color: #ddd; display: flex; justify-content: center;
           align-items: center; min-height: 100vh; }
    .container { background: #1a1d27; padding: 2rem; border-radius: 12px;
                 box-shadow: 0 8px 32px rgba(0,0,0,0.6); width: 400px; max-width: 90%; }
    h2 { margin-bottom: 1.5rem; color: #fff; text-align: center; }
    .form-group { margin-bottom: 1rem; }
    label { display: block; margin-bottom: 0.3rem; color: #aaa; }
    input, select { width: 100%; padding: 0.75rem; border: 1px solid #333;
                    background: #12141c; color: #fff; border-radius: 6px; }
    button { width: 100%; padding: 0.75rem; border: none; border-radius: 6px;
             background: #4a6cf7; color: white; font-weight: bold; cursor: pointer;
             margin-top: 0.5rem; }
    button:hover { background: #3651d5; }
    .error { color: #ff5555; margin-top: 0.5rem; }
    .success { color: #55ff55; margin-top: 0.5rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { padding: 0.5rem; border-bottom: 1px solid #333; text-align: left; }
    a { color: #4a6cf7; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    .logout { color: #ff5555; }
</style>
'''

def get_db():
    conn = sqlite3.connect('/opt/cheat-server/database.db')
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
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
        ''')

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
        if ':' not in pair:
            continue
        k, v = pair.split(':', 1)
        k = k.strip().strip('"\'')
        v = v.strip().strip('"\'')
        if v.lower() == 'true':
            v = True
        elif v.lower() == 'false':
            v = False
        elif v.isdigit():
            v = int(v)
        data[k] = v
    return data if data else None

@app.before_request
def log_auth():
    if request.path == '/auth':
        app.logger.info(f"AUTH RAW: {request.get_data()[:200]}")

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
        dll_path = os.path.join('cheat/Shared/internal.dll') if os.path.exists('cheat/Shared/internal.dll') else 'cheat/internal.dll'
        if not os.path.exists(dll_path):
            return jsonify({'error': 'DLL not found'}), 500
        return send_file(dll_path, as_attachment=True, download_name='internal.dll', mimetype='application/octet-stream')
    elif file == 'exe':
        exe_path = 'cheat/Shared/Overlay.exe'
        if not os.path.exists(exe_path):
            return jsonify({'error': 'Overlay.exe not found'}), 500
        return send_file(exe_path, as_attachment=True, download_name='Overlay.exe', mimetype='application/octet-stream')
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/register', methods=['GET'])
def register_form():
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container">
            <h2>Регистрация</h2>
            <form id="regForm">
                <div class="form-group"><input type="text" id="username" placeholder="Логин" required></div>
                <div class="form-group"><input type="password" id="password" placeholder="Пароль" required></div>
                <div class="form-group"><input type="text" id="key" placeholder="Ключ доступа" required></div>
                <button type="submit">Зарегистрироваться</button>
                <div id="msg" class="msg"></div>
            </form>
            <p style="margin-top:1rem; text-align:center;">Уже есть аккаунт? <a href="/login">Войти</a></p>
        </div>
        <script>
            document.getElementById('regForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const msg = document.getElementById('msg');
                msg.className = '';
                msg.textContent = 'Регистрация...';
                const res = await fetch('/register', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value,
                        key: document.getElementById('key').value
                    }})
                }});
                const data = await res.json();
                if (data.error) {{
                    msg.className = 'error';
                    msg.textContent = 'Ошибка: ' + data.error;
                }} else {{
                    msg.className = 'success';
                    msg.textContent = 'Успешно! Теперь войдите в лоадере.';
                }}
            }});
        </script>
    ''')

@app.route('/register', methods=['POST'])
def register_api():
    data = request.json
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
    return jsonify({'success': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template_string(f'{BASE_CSS}<div class="container"><h2>Вход</h2><div class="error">Заполните все поля</div></div>')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session['user_id'] = user['id']
            return redirect(url_for('user_panel'))
        return render_template_string(f'{BASE_CSS}<div class="container"><h2>Вход</h2><div class="error">Неверный логин или пароль</div></div>')
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container">
            <h2>Вход</h2>
            <form method="POST">
                <div class="form-group"><input type="text" name="username" placeholder="Логин" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Пароль" required></div>
                <button type="submit">Войти</button>
            </form>
            <p style="margin-top:1rem; text-align:center;">Нет аккаунта? <a href="/register">Регистрация</a></p>
        </div>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
@login_required
def user_panel():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    expiry = user['subscription_expiry']
    days_left = max(0, (expiry - int(time.time())) // 86400)
    expiry_str = datetime.utcfromtimestamp(expiry).strftime('%d.%m.%Y')
    hwid = user['hwid'] if user['hwid'] else 'Не привязан'
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container">
            <div class="header">
                <h2>Личный кабинет</h2>
                <a class="logout" href="/logout">Выйти</a>
            </div>
            <table>
                <tr><th>Логин</th><td>{user['username']}</td></tr>
                <tr><th>HWID</th><td>{hwid}</td></tr>
                <tr><th>Подписка до</th><td>{expiry_str} ({days_left} дн.)</td></tr>
            </table>
        </div>
    ''')

# ===== ИЗМЕНЕННАЯ АДМИН-ПАНЕЛЬ (работает с БД) =====

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template_string(f'{BASE_CSS}<div class="container"><h2>Админ</h2><div class="error">Заполните все поля</div></div>')
        
        # Проверяем в базе данных админов
        db = get_db()
        admin = db.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        
        if admin and bcrypt.checkpw(password.encode(), admin['password_hash'].encode()):
            session['admin'] = True
            session['admin_id'] = admin['id']
            return redirect(url_for('admin_panel'))
        
        return render_template_string(f'{BASE_CSS}<div class="container"><h2>Админ</h2><div class="error">Неверные данные</div></div>')
    
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container">
            <h2>Администрирование</h2>
            <form method="POST">
                <div class="form-group"><input type="text" name="username" placeholder="Администратор" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Пароль" required></div>
                <button type="submit">Войти</button>
            </form>
            <p style="margin-top:1rem; text-align:center; color:#666; font-size:0.9rem;">
                (Используйте администратора из базы данных)
            </p>
        </div>
    ''')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/panel')
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    keys = db.execute('SELECT * FROM keys').fetchall()
    admins = db.execute('SELECT * FROM admins').fetchall()
    
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container" style="width:800px;">
            <div class="header"><h2>Панель управления</h2><a class="logout" href="/admin/logout">Выйти</a></div>
            
            <h3>Администраторы</h3>
            <table>
                <tr><th>ID</th><th>Логин</th></tr>
                {''.join(f"<tr><td>{a['id']}</td><td>{a['username']}</td></tr>" for a in admins)}
            </table>
            
            <h3 style="margin-top:2rem;">Пользователи</h3>
            <table>
                <tr><th>ID</th><th>Логин</th><th>HWID</th><th>Истекает</th><th>Дней</th></tr>
                {''.join(f"<tr><td>{u['id']}</td><td>{u['username']}</td><td>{u['hwid'] or '—'}</td><td>{datetime.utcfromtimestamp(u['subscription_expiry']).strftime('%d.%m.%Y')}</td><td>{max(0,(u['subscription_expiry']-int(time.time()))//86400)}</td></tr>" for u in users)}
            </table>
            
            <h3 style="margin-top:2rem;">Ключи</h3>
            <table>
                <tr><th>Ключ</th><th>Дней</th><th>Использован</th></tr>
                {''.join(f"<tr><td>{k['key']}</td><td>{k['duration_days']}</td><td>{k['used_by'] or 'Нет'}</td></tr>" for k in keys)}
            </table>
            
            <a href="/admin/generate"><button style="margin-top:1rem;">Сгенерировать новый ключ</button></a>
            <br>
            <a href="/admin/add_admin"><button style="margin-top:0.5rem;">Добавить администратора</button></a>
        </div>
    ''')

@app.route('/admin/add_admin', methods=['GET', 'POST'])
@admin_required
def admin_add_admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template_string(f'{BASE_CSS}<div class="container"><h2>Ошибка</h2><div class="error">Заполните все поля</div><a href="/admin/add_admin">Назад</a></div>')
        
        db = get_db()
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        try:
            db.execute('INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)',
                      (username, password_hash, int(time.time())))
            db.commit()
            return render_template_string(f'''
                {BASE_CSS}
                <div class="container">
                    <h2>Администратор добавлен</h2>
                    <div class="success">Пользователь {username} добавлен как администратор</div>
                    <a href="/admin/panel">Назад в панель</a>
                </div>
            ''')
        except sqlite3.IntegrityError:
            return render_template_string(f'{BASE_CSS}<div class="container"><h2>Ошибка</h2><div class="error">Администратор уже существует</div><a href="/admin/add_admin">Назад</a></div>')
    
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container">
            <h2>Добавить администратора</h2>
            <form method="POST">
                <div class="form-group"><input type="text" name="username" placeholder="Логин" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Пароль" required></div>
                <button type="submit">Добавить</button>
            </form>
            <a href="/admin/panel">Назад</a>
        </div>
    ''')

@app.route('/admin/generate', methods=['GET','POST'])
@admin_required
def admin_generate():
    if request.method == 'POST':
        days = int(request.form['days'])
        key = secrets.token_hex(8).upper()
        db = get_db()
        db.execute('INSERT INTO keys (key, duration_days, created_by) VALUES (?,?,?)', (key, days, 'admin'))
        db.commit()
        return render_template_string(f'{BASE_CSS}<div class="container"><h2>Ключ создан</h2><p>Ключ: <strong>{key}</strong> ({days} дн.)</p><a href="/admin/panel">Назад</a></div>')
    return render_template_string(f'''
        {BASE_CSS}
        <div class="container">
            <h2>Генерация ключа</h2>
            <form method="POST">
                <div class="form-group"><input type="number" name="days" placeholder="Срок (дней)" required></div>
                <button type="submit">Создать</button>
            </form>
            <a href="/admin/panel">Назад</a>
        </div>
    ''')

if __name__ == '__main__':
    init_db()
    
    # Добавляем администратора по умолчанию, если его нет
    with get_db() as db:
        admin_check = db.execute('SELECT id FROM admins WHERE username = ?', ('mtrr',)).fetchone()
        if not admin_check:
            password_hash = bcrypt.hashpw('8426mTer1or'.encode(), bcrypt.gensalt()).decode()
            db.execute('INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)',
                      ('mtrr', password_hash, int(time.time())))
            db.commit()
            print("Администратор mtrr добавлен в базу данных")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
