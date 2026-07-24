import re
with open('app.py', 'r') as f:
    content = f.read()
old = '''def migrate_db():
    """Добавляет новые столбцы, если их ещё нет (безопасно для старых БД)."""
    conn = get_db()
    cur = conn.cursor()
    cols = [col[1] for col in cur.execute('PRAGMA table_info(users)').fetchall()]
    if 'display_name' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN display_name TEXT UNIQUE DEFAULT NULL')
    if 'avatar_path' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT NULL')
    conn.commit()
    conn.close()'''
new = '''def migrate_db():
    """Добавляет новые столбцы, если их ещё нет (безопасно для старых БД)."""
    conn = get_db()
    cur = conn.cursor()
    cols = [col[1] for col in cur.execute('PRAGMA table_info(users)').fetchall()]
    if 'display_name' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN display_name TEXT')
        cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name)')
    if 'avatar_path' not in cols:
        cur.execute('ALTER TABLE users ADD COLUMN avatar_path TEXT')
    conn.commit()
    conn.close()'''
content = content.replace(old, new)
with open('app.py', 'w') as f:
    f.write(content)
