"""
Общие фикстуры pytest для Butler.
"""
import os
import pytest


@pytest.fixture(autouse=True)
def isolate_system_commands(monkeypatch):
    """Unit tests must never change the machine's actual firewall."""
    import subprocess
    import app.firewall as fw

    def forbidden(*args, **kwargs):
        raise AssertionError('System commands must be explicitly mocked in unit tests')

    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(fw, '_docker_published_host_ports', lambda: set())
    monkeypatch.setattr(fw, '_try_command', lambda *args, **kwargs: (True, 'Status: active'))


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / 'test.sqlite3')

    # ВАЖНО: изоляция от реального butler.env.
    # create_app() ищет butler.env в cwd/родителе и грузит его с override=True —
    # это перетирает тестовые креды и BUTLER_DATABASE реальными значениями
    # (логин ломается => везде 302, тесты бьют по боевой БД).
    # _find_env_file() принимает BUTLER_ENV_FILE только если это существующий
    # файл, иначе идёт искать butler.env в cwd/parent. Поэтому недостаточно
    # указать несуществующий путь — создаём РЕАЛЬНЫЙ пустой env-файл в tmp_path,
    # чтобы is_file() вернул True и поиск не дошёл до реального butler.env.
    empty_env = tmp_path / 'test.env'
    empty_env.write_text('')
    os.environ['BUTLER_ENV_FILE']   = str(empty_env)
    os.environ['BUTLER_SECRET_KEY'] = 'test-secret-key'
    os.environ['BUTLER_DATABASE']   = db_path
    os.environ['BUTLER_ADMIN_USER'] = 'admin'
    os.environ['BUTLER_ADMIN_PASS'] = 'password'
    os.environ['BUTLER_PORT']       = '5050'

    from app import create_app
    application = create_app()
    application.config['TESTING'] = True

    with application.app_context():
        from app.db import init_db
        init_db()

    yield application

    # Очищаем env чтобы не протекало между тестами
    for key in ['BUTLER_ENV_FILE', 'BUTLER_SECRET_KEY', 'BUTLER_DATABASE',
                'BUTLER_ADMIN_USER', 'BUTLER_ADMIN_PASS', 'BUTLER_PORT']:
        os.environ.pop(key, None)


def get_csrf(client):
    """Получить CSRF-токен из сессии клиента.

    Контекст-процессор кладёт токен в сессию при рендере любого шаблона,
    поэтому сначала делаем GET (login или, после входа, редирект на index —
    в обоих случаях рендерится base.html), затем читаем токен из сессии.
    """
    client.get('/login', follow_redirects=True)
    with client.session_transaction() as sess:
        return sess.get('csrf_token')


def post(client, url, data=None, **kwargs):
    """POST с автоматически подставленным CSRF-токеном."""
    payload = dict(data or {})
    payload.setdefault('csrf_token', get_csrf(client))
    return client.post(url, data=payload, **kwargs)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Клиент с активной сессией (login освобождён от CSRF-проверки)."""
    client.post('/login', data={'username': 'admin', 'password': 'password'})
    return client
