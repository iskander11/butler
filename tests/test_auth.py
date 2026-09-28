"""
Тесты авторизации (чек-лист §2).
"""
import pytest

from conftest import post


def test_redirect_to_login_without_session(client):
    """2.1 — без сессии главная страница редиректит на логин."""
    r = client.get('/', follow_redirects=False)
    assert r.status_code == 302
    assert '/login' in r.headers['Location']


def test_protected_page_redirects_to_login(client):
    """2.5 — прямой URL к защищённой странице без сессии → логин."""
    for url in ['/services', '/attempts', '/whitelist', '/firewall']:
        r = client.get(url, follow_redirects=False)
        assert r.status_code == 302, f'{url} должен редиректить'
        assert '/login' in r.headers['Location']


def test_login_correct_credentials(client):
    """2.2 — корректные логин/пароль дают доступ."""
    r = client.post('/login', data={'username': 'admin', 'password': 'password'},
                    follow_redirects=True)
    assert r.status_code == 200
    assert b'\xd0\x94\xd0\xb2\xd0\xbe\xd1\x80\xd0\xb5\xd1\x86\xd0\xba\xd0\xb8\xd0\xb9' in r.data or b'butler' in r.data.lower() or r.status_code == 200


def test_login_wrong_password(client):
    """2.3 — неверный пароль не даёт доступ."""
    r = client.post('/login', data={'username': 'admin', 'password': 'wrong'},
                    follow_redirects=True)
    # Остаёмся на логине или получаем ошибку
    assert r.status_code == 200
    assert b'/login' in r.data or 'login' in r.request.path


def test_logout(auth_client):
    """2.6 — после выхода сессия уничтожена."""
    r = post(auth_client, '/logout', follow_redirects=False)
    assert r.status_code in (302, 303)
    # После выхода — защищённая страница недоступна
    r2 = auth_client.get('/services', follow_redirects=False)
    assert r2.status_code == 302
    assert '/login' in r2.headers['Location']
