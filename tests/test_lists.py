"""
Тесты белого списка, включая CIDR-подсети.
"""
from conftest import post


def add_whitelist(client, ip, owner='', comment=''):
    return post(client, '/whitelist', data={
        'ip_address': ip,
        'owner_name': owner,
        'comment': comment,
    }, follow_redirects=True)


def test_whitelist_page_loads(auth_client):
    """4.1 — страница белого списка открывается."""
    r = auth_client.get('/whitelist')
    assert r.status_code == 200


def test_whitelist_add_single_ip(auth_client):
    """4.2 — добавить одиночный IP."""
    r = add_whitelist(auth_client, '192.168.1.10', owner='Тест')
    assert r.status_code == 200
    assert b'192.168.1.10' in r.data


def test_whitelist_add_subnet(auth_client):
    """4.3 — добавить подсеть CIDR."""
    r = add_whitelist(auth_client, '188.243.183.0/24', owner='Клиент')
    assert r.status_code == 200
    assert b'188.243.183.0/24' in r.data


def test_whitelist_invalid_ip(auth_client):
    """4.4 — некорректный IP не добавляется."""
    r = add_whitelist(auth_client, '999.999.x.x')
    assert r.status_code == 200
    assert b'999.999.x.x' not in r.data


def test_whitelist_delete(auth_client, app):
    """4.6 — удаление записи из белого списка."""
    add_whitelist(auth_client, '1.2.3.4')
    with app.app_context():
        from app.db import get_db
        entry = get_db().execute(
            "SELECT id FROM whitelist_entries WHERE ip_address IN ('1.2.3.4', '1.2.3.4/32')"
        ).fetchone()
        assert entry is not None
        entry_id = entry['id']

    r = post(auth_client, f'/whitelist/{entry_id}/delete', follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.db import get_db
        entry = get_db().execute(
            "SELECT id FROM whitelist_entries WHERE ip_address IN ('1.2.3.4', '1.2.3.4/32') AND enabled=1"
        ).fetchone()
        assert entry is None


def test_blacklist_routes_removed(auth_client):
    """Чёрный список вырезан — маршрутов больше нет."""
    r = auth_client.get('/blacklist')
    assert r.status_code == 404
