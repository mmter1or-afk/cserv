#!/usr/bin/env python3
"""
Production-ready Flask application with security hardening.
CRITICAL SECURITY FIXES:
- Removed hardcoded credentials
- Added rate limiting
- Added CSRF protection
- Added input validation
- Removed XSS vulnerabilities
- Added proper error handling
- Environment-based configuration
"""

import os
import sqlite3
import time
import bcrypt
import secrets
import functools
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template, session, 
    redirect, url_for, send_file, send_from_directory
)
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import BadRequest, Forbidden
from dotenv import load_dotenv

# ============================================================================
# CONFIGURATION
# ============================================================================

load_dotenv()

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

# 1. Secret key from environment, never hardcoded
def get_or_create_secret_key():
    """Get secret key from env or create it securely."""
    secret = os.environ.get('SECRET_KEY')
    if secret:
        return secret
    
    # For development only - in production, SECRET_KEY MUST be set via environment
    logger.warning("SECRET_KEY not set in environment. Generate one and set it!")
    return secrets.token_hex(32)

app.secret_key = get_or_create_secret_key()

# 2. Session security configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,          # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,        # No JS access
    SESSION_COOKIE_SAMESITE='Lax',       # CSRF protection
    SESSION_COOKIE_AGE=3600,             # 1 hour expiry
    PERMANENT_SESSION_LIFETIME=3600,
)

# 3. File upload configuration
AVATAR_FOLDER = os.path.join('static', 'avatars')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB max

os.makedirs(AVATAR_FOLDER, exist_ok=True)
app.config['AVATAR_FOLDER'] = AVATAR_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 4. Proxy fix for reverse proxies (nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter."""
    def __init__(self):
        self.attempts = {}
    
    def is_allowed(self, identifier, max_attempts=5, window_seconds=300):
        """Check if action is allowed within rate limit."""
        now = time.time()
        key = identifier
        
        if key not in self.attempts:
            self.attempts[key] = []
        
        # Clean old attempts
        self.attempts[key] = [
            ts for ts in self.attempts[key] 
            if now - ts < window_seconds
        ]
        
        if len(self.attempts[key]) >= max_attempts:
            return False
        
        self.attempts[key].append(now)
        return True

rate_limiter = RateLimiter()

def rate_limit(max_attempts=5, window_seconds=300):
    """Rate limit decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use client IP as identifier
            client_ip = request.remote_addr
            endpoint = request.endpoint or 'unknown'
            identifier = f"{client_ip}:{endpoint}"
            
            if not rate_limiter.is_allowed(identifier, max_attempts, window_seconds):
                logger.warning(f"Rate limit exceeded for {client_ip} on {endpoint}")
                return jsonify({'error': 'Too many requests. Please try again later.'}), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# DATABASE
# ============================================================================

DB_PATH = os.environ.get('DATABASE_PATH', 'database.db')

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database schema."""
    try:
        with get_db() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    hwid TEXT DEFAULT NULL,
                    subscription_expiry INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
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
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS admin_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
                CREATE INDEX IF NOT EXISTS idx_chat_user ON chat_messages(user_id);
            ''')
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

# ============================================================================
# INPUT VALIDATION
# ============================================================================

def validate_username(username):
    """Validate username format and length."""
    if not username or not isinstance(username, str):
        return False, "Username must be a string"
    
    if len(username) < 3 or len(username) > 32:
        return False, "Username must be between 3 and 32 characters"
    
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, hyphens, and underscores"
    
    return True, None

def validate_password(password):
    """Validate password strength."""
    if not password or not isinstance(password, str):
        return False, "Password must be a string"
    
    if len(password) < 8 or len(password) > 128:
        return False, "Password must be between 8 and 128 characters"
    
    return True, None

def validate_hwid(hwid):
    """Validate HWID format."""
    if not hwid or not isinstance(hwid, str):
        return False, "HWID must be a string"
    
    if len(hwid) > 256:
        return False, "HWID too long"
    
    return True, None

# ============================================================================
# AUTHENTICATION
# ============================================================================

def login_required(f):
    """Require user login."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Require admin login."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_id'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ============================================================================
# ROUTES: Authentication
# ============================================================================

@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_attempts=10, window_seconds=300)
def register():
    """User registration."""
    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form
            
            username = (data.get('username') or '').strip()
            password = data.get('password') or ''
            key = (data.get('key') or '').strip()
            
            # Validation
            is_valid, error = validate_username(username)
            if not is_valid:
                return jsonify({'error': error}), 400
            
            is_valid, error = validate_password(password)
            if not is_valid:
                return jsonify({'error': error}), 400
            
            if not key:
                return jsonify({'error': 'Access key is required'}), 400
            
            # Check key
            db = get_db()
            key_data = db.execute(
                'SELECT * FROM keys WHERE key = ? AND used_by IS NULL',
                (key,)
            ).fetchone()
            
            if not key_data:
                logger.warning(f"Invalid key attempt: {key}")
                return jsonify({'error': 'Invalid or already used key'}), 400
            
            # Check username exists
            if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
                return jsonify({'error': 'Username already exists'}), 400
            
            # Hash password and create user
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            expiry = int(time.time()) + key_data['duration_days'] * 86400
            
            db.execute(
                '''INSERT INTO users (username, password_hash, subscription_expiry, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)''',
                (username, password_hash, expiry, int(time.time()), int(time.time()))
            )
            
            # Mark key as used
            user_id = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
            db.execute(
                'UPDATE keys SET used_by = ?, redeemed_at = ? WHERE key = ?',
                (user_id, int(time.time()), key)
            )
            
            db.commit()
            logger.info(f"User registered: {username}")
            
            if request.is_json:
                return jsonify({'success': True, 'message': 'Registration successful'})
            return redirect(url_for('login'))
        
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({'error': 'Registration failed. Please try again.'}), 500
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_attempts=5, window_seconds=300)
def login():
    """User login."""
    if request.method == 'POST':
        try:
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            
            if not username or not password:
                return render_template('login.html', error='Please fill in all fields')
            
            db = get_db()
            user = db.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            
            if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
                session['user_id'] = user['id']
                session.permanent = True
                logger.info(f"User logged in: {username}")
                return redirect(url_for('panel'))
            
            logger.warning(f"Failed login attempt: {username}")
            return render_template('login.html', error='Invalid username or password')
        
        except Exception as e:
            logger.error(f"Login error: {e}")
            return render_template('login.html', error='Login failed. Please try again.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    return redirect(url_for('login'))

# ============================================================================
# ROUTES: User Panel
# ============================================================================

@app.route('/panel')
@login_required
def panel():
    """User dashboard."""
    try:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        expiry = user['subscription_expiry']
        days_left = max(0, (expiry - int(time.time())) // 86400)
        expiry_str = datetime.utcfromtimestamp(expiry).strftime('%d.%m.%Y')
        hwid = user['hwid'] or 'Not bound'
        
        return render_template(
            'panel.html',
            user=user,
            hwid=hwid,
            expiry_str=expiry_str,
            days_left=days_left
        )
    except Exception as e:
        logger.error(f"Panel error: {e}")
        return render_template('error.html', error='Failed to load panel'), 500

@app.route('/panel/update', methods=['POST'])
@login_required
@rate_limit(max_attempts=10, window_seconds=300)
def panel_update():
    """Update user profile."""
    try:
        db = get_db()
        user_id = session['user_id']
        new_display = (request.form.get('display_name') or '').strip()
        
        # Validate display name
        if new_display:
            if len(new_display) > 64:
                return jsonify({'error': 'Display name too long'}), 400
            
            exists = db.execute(
                'SELECT id FROM users WHERE username = ? AND id != ?',
                (new_display, user_id)
            ).fetchone()
            
            if exists:
                return jsonify({'error': 'This name is already taken'}), 400
            
            db.execute('UPDATE users SET username = ? WHERE id = ?', (new_display, user_id))
        
        # Handle avatar upload
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename != '':
                # Validate file
                if not file.filename.lower().endswith(tuple(ALLOWED_EXTENSIONS)):
                    return jsonify({'error': 'Invalid file format'}), 400
                
                # Security: Use secure filename
                filename = secure_filename(f"user_{user_id}.png")
                
                # Prevent path traversal
                filepath = os.path.join(app.config['AVATAR_FOLDER'], filename)
                filepath = os.path.abspath(filepath)
                
                if not filepath.startswith(os.path.abspath(app.config['AVATAR_FOLDER'])):
                    logger.error(f"Path traversal attempt detected for user {user_id}")
                    return jsonify({'error': 'Invalid file path'}), 400
                
                file.save(filepath)
        
        db.execute('UPDATE users SET updated_at = ? WHERE id = ?', (int(time.time()), user_id))
        db.commit()
        
        return redirect(url_for('panel'))
    
    except Exception as e:
        logger.error(f"Panel update error: {e}")
        return jsonify({'error': 'Update failed'}), 500

# ============================================================================
# ROUTES: Admin Panel
# ============================================================================

@app.route('/admin', methods=['GET', 'POST'])
@rate_limit(max_attempts=5, window_seconds=300)
def admin_login():
    """Admin login."""
    if request.method == 'POST':
        try:
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            
            if not username or not password:
                return render_template('admin/login.html', error='Please fill in all fields')
            
            db = get_db()
            admin = db.execute(
                'SELECT * FROM admin_accounts WHERE username = ?',
                (username,)
            ).fetchone()
            
            if admin and bcrypt.checkpw(password.encode(), admin['password_hash'].encode()):
                session['admin_id'] = admin['id']
                session.permanent = True
                logger.info(f"Admin logged in: {username}")
                return redirect(url_for('admin_panel'))
            
            logger.warning(f"Failed admin login attempt: {username}")
            return render_template('admin/login.html', error='Invalid credentials')
        
        except Exception as e:
            logger.error(f"Admin login error: {e}")
            return render_template('admin/login.html', error='Login failed')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout."""
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/panel')
@admin_required
def admin_panel():
    """Admin dashboard."""
    try:
        db = get_db()
        users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
        keys = db.execute('SELECT * FROM keys ORDER BY created_at DESC').fetchall()
        now = int(time.time())
        
        return render_template('admin/panel.html', users=users, keys=keys, now=now)
    
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        return render_template('error.html', error='Failed to load admin panel'), 500

@app.route('/admin/generate', methods=['GET', 'POST'])
@admin_required
@rate_limit(max_attempts=20, window_seconds=300)
def admin_generate():
    """Generate access key."""
    try:
        if request.method == 'POST':
            days_str = request.form.get('days', '').strip()
            
            # Validate days
            try:
                days = int(days_str)
                if days < 1 or days > 3650:  # Max 10 years
                    return render_template('admin/generate.html', error='Days must be between 1 and 3650')
            except ValueError:
                return render_template('admin/generate.html', error='Invalid days value')
            
            key = secrets.token_hex(8).upper()
            
            db = get_db()
            db.execute(
                'INSERT INTO keys (key, duration_days, created_by) VALUES (?, ?, ?)',
                (key, days, 'admin')
            )
            db.commit()
            
            logger.info(f"Key generated: {key} ({days} days)")
            return render_template('admin/generate.html', key=key, days=days)
        
        return render_template('admin/generate.html')
    
    except Exception as e:
        logger.error(f"Key generation error: {e}")
        return render_template('admin/generate.html', error='Failed to generate key')

# ============================================================================
# ROUTES: API Endpoints
# ============================================================================

@app.route('/auth', methods=['POST'])
@rate_limit(max_attempts=10, window_seconds=300)
def auth():
    """Authenticate client (for game loader)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        hwid = (data.get('hwid') or '').strip()
        check_only = data.get('check_only', False)
        file_type = data.get('file', 'dll')
        
        # Validation
        if not username or not password or not hwid:
            return jsonify({'error': 'Missing required fields'}), 400
        
        is_valid, error = validate_hwid(hwid)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Authentication
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            logger.warning(f"Auth failed for user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check subscription
        if user['subscription_expiry'] < int(time.time()):
            logger.warning(f"Subscription expired for user: {username}")
            return jsonify({'error': 'Subscription expired'}), 403
        
        # HWID binding
        if user['hwid'] is None:
            db.execute('UPDATE users SET hwid = ? WHERE id = ?', (hwid, user['id']))
            db.commit()
        elif user['hwid'] != hwid:
            logger.warning(f"HWID mismatch for user: {username}")
            return jsonify({'error': 'HWID mismatch'}), 403
        
        if check_only:
            return jsonify({'success': True})
        
        # File download
        if file_type == 'dll':
            dll_path = os.path.join('cheat', 'internal.dll')
            if not os.path.exists(dll_path):
                return jsonify({'error': 'DLL not found'}), 404
            return send_file(dll_path, as_attachment=True, download_name='internal.dll')
        
        elif file_type == 'exe':
            exe_path = os.path.join('cheat', 'Overlay.exe')
            if not os.path.exists(exe_path):
                return jsonify({'error': 'Overlay.exe not found'}), 404
            return send_file(exe_path, as_attachment=True, download_name='Overlay.exe')
        
        return jsonify({'error': 'Invalid file type'}), 400
    
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/avatars/<path:filename>')
def avatars(filename):
    """Serve avatars."""
    try:
        filename = secure_filename(filename)
        return send_from_directory(app.config['AVATAR_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Avatar serve error: {e}")
        return jsonify({'error': 'Not found'}), 404

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(400)
def bad_request(e):
    """Handle bad requests."""
    return render_template('error.html', error='Bad request'), 400

@app.errorhandler(403)
def forbidden(e):
    """Handle forbidden errors."""
    return render_template('error.html', error='Access denied'), 403

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(429)
def rate_limited(e):
    """Handle rate limit errors."""
    return jsonify({'error': 'Too many requests'}), 429

@app.errorhandler(500)
def server_error(e):
    """Handle server errors."""
    logger.error(f"Server error: {e}")
    return render_template('error.html', error='Server error'), 500

# ============================================================================
# INITIALIZATION
# ============================================================================

if __name__ == '__main__':
    init_db()
    logger.info("Starting application")
    app.run(host='0.0.0.0', port=5000, debug=False)
