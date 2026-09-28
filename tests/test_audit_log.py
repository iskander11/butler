"""
Тесты журнала действий (чек-лист §11).
"""
import pytest

from conftest import post


def test_audit_log_page_loads(auth_client):
    """11 — страница журнала открывается."""
    r = auth_client.get('/audit-log')
    assert r.status_code == 200


def test_audit_log_records_service_create(auth_client, app):
    """11.1 — создание сервиса фиксируется в журнале."""
    post(auth_client, '/services', data={
        'name': 'AUDIT_TEST', 'ports_raw': '1234',
        'protocol': 'tcp', 'description': ''
    }, follow_redirects=True)

    with app.app_context():
        from app.db import get_db
        entries = get_db().execute(
            "SELECT * FROM audit_log WHERE action='create' AND target_type='service'"
        ).fetchall()
        assert len(entries) > 0


def test_audit_log_records_whitelist_add(auth_client, app):
    """11.1 — добавление в белый список фиксируется."""
    post(auth_client, '/whitelist', data={
        'ip_address': '11.22.33.44', 'owner_name': '', 'comment': ''
    }, follow_redirects=True)

    with app.app_context():
        from app.db import get_db
        entries = get_db().execute(
            "SELECT * FROM audit_log WHERE target_type='ip'"
        ).fetchall()
        assert len(entries) > 0


def test_audit_log_records_apply_not_mode(auth_client, app):
    """Смена режима удалена — в журнале её больше нет как UI-действия."""
    r = post(auth_client, '/settings/firewall-mode', data={'mode': 'blacklist'})
    assert r.status_code == 404


def test_audit_log_persists_after_restart(app):
    """11.3 — записи сохраняются в БД (не в памяти)."""
    with app.app_context():
        from app.db import get_db
        db = get_db()
        db.execute(
            'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
            ('test', 'unit_test', 'persist_check', 'автотест')
        )
        db.commit()
        count_before = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    # Новый контекст — имитирует перезапуск
    with app.app_context():
        from app.db import get_db
        count_after = get_db().execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert count_after == count_before
