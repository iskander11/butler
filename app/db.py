import sqlite3
from flask import current_app, g


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    port INTEGER NOT NULL UNIQUE,
    ports_raw TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    description TEXT,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whitelist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    owner_name TEXT,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    service_name TEXT NOT NULL,
    port INTEGER NOT NULL,
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def parse_ports_raw(ports_raw):
    """
    Разобрать строку портов вида "80, 443, 8000-8100" в список целых чисел.
    Поддерживает: одиночные порты через запятую, диапазоны через дефис, смесь.
    Возвращает отсортированный список уникальных портов.
    """
    result = set()
    if not ports_raw:
        return []
    for part in ports_raw.replace(' ', '').split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                result.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                result.add(int(part))
            except ValueError:
                pass
    return sorted(p for p in result if 1 <= p <= 65535)


def migrate_db(db):
    """Применить миграции к существующей БД (добавить отсутствующие колонки)."""
    cols = {row[1] for row in db.execute("PRAGMA table_info(services)").fetchall()}
    if 'ports_raw' not in cols:
        db.execute("ALTER TABLE services ADD COLUMN ports_raw TEXT NOT NULL DEFAULT ''")
        db.execute("UPDATE services SET ports_raw = CAST(port AS TEXT) WHERE ports_raw = ''")
        db.commit()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()


def get_setting(key, default=None):
    db = get_db()
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    if row is None:
        return default
    return row['value']


def set_setting(key, value):
    """
    Установить значение настройки.
    Используем INSERT OR REPLACE вместо INSERT ... ON CONFLICT
    для совместимости с SQLite < 3.24 (Astra Linux 1.8).
    """
    db = get_db()
    db.execute(
        'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
        (key, value)
    )
    db.commit()


def seed_demo_data():
    db = get_db()

    services_count = db.execute('SELECT COUNT(*) AS count FROM services').fetchone()['count']
    if services_count == 0:
        db.executemany(
            'INSERT INTO services (name, port, protocol, description) VALUES (?, ?, ?, ?)',
            [
                ('CRM', 8011, 'tcp', 'Внутренний CRM сервис'),
                ('API', 8080, 'tcp', 'Основной API сервис'),
                ('Admin Panel', 9000, 'tcp', 'Административная панель'),
            ]
        )

    attempts_count = db.execute('SELECT COUNT(*) AS count FROM attempts').fetchone()['count']
    if attempts_count == 0:
        db.executemany(
            'INSERT INTO attempts (ip_address, service_name, port, attempts_count, status, note) VALUES (?, ?, ?, ?, ?, ?)',
            [
                ('1.2.3.4', 'CRM', 8011, 4, 'new', 'Похоже на клиента'),
                ('5.6.7.8', 'API', 8080, 2, 'new', 'Неизвестный адрес'),
                ('9.9.9.9', 'Admin Panel', 9000, 7, 'blocked', 'Подозрительная активность'),
            ]
        )

    whitelist_count = db.execute('SELECT COUNT(*) AS count FROM whitelist_entries').fetchone()['count']
    if whitelist_count == 0:
        db.execute(
            'INSERT INTO whitelist_entries (ip_address, owner_name, comment) VALUES (?, ?, ?)',
            ('10.10.10.10', 'Тестовый клиент', 'Разрешен для проверки интерфейса')
        )

    mode_exists = db.execute("SELECT COUNT(*) AS count FROM settings WHERE key = 'firewall_mode'").fetchone()['count']
    if mode_exists == 0:
        db.execute("INSERT INTO settings (key, value) VALUES ('firewall_mode', 'whitelist')")

    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA_SQL)
        db.commit()
        migrate_db(db)

    @app.cli.command('init-db')
    def init_db_command():
        init_db()
        print('Database initialized.')
