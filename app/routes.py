import ipaddress
import secrets
import sqlite3
import subprocess
from pathlib import Path

import click
from flask import (Blueprint, abort, flash, redirect, render_template,
                   request, session, url_for)
from .auth import check_auth, login_required
from .db import get_db, parse_ports_raw
from . import firewall as fw
from logparse import parse_log_line

bp = Blueprint('main', __name__)


def validate_ip_address(value):
    """Принимает одиночный IP или CIDR-подсеть. Возвращает нормализованную строку или None."""
    try:
        net = ipaddress.ip_network(value, strict=False)
        return str(net)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# CSRF-защита
# ---------------------------------------------------------------------------

def _get_csrf_token():
    """Вернуть CSRF-токен сессии, создав его при отсутствии."""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(16)
        session['csrf_token'] = token
    return token


@bp.context_processor
def inject_csrf_token():
    """Прокинуть csrf_token во все шаблоны."""
    return {'csrf_token': _get_csrf_token()}


def _check_csrf():
    """Проверить CSRF-токен POST-запроса. При несовпадении — 400."""
    session_token = session.get('csrf_token')
    form_token = request.form.get('csrf_token', '')
    if not session_token or not secrets.compare_digest(str(session_token), str(form_token)):
        abort(400)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@bp.cli.command('firewall-apply')
def firewall_apply_command():
    """Сгенерировать и применить правила через активный бекенд."""
    try:
        generated_file, target_file, backup_file = fw.apply_firewall_rules()
        click.echo(f'Правила успешно применены: {generated_file}')
        if target_file:
            click.echo(f'Target обновлён: {target_file}')
        if backup_file:
            click.echo(f'Backup сохранён в: {backup_file}')
    except Exception as exc:
        raise click.ClickException(str(exc))


@bp.cli.command('firewall-reset')
def firewall_reset_command():
    """Сбросить правила Butler через активный бекенд."""
    try:
        target_file, backup_file = fw.reset_firewall_rules()
        if target_file:
            click.echo(f'Butler-правила сброшены: {target_file}')
        else:
            click.echo('Butler-правила сброшены (UFW reset).')
        if backup_file:
            click.echo(f'Backup сохранён в: {backup_file}')
    except Exception as exc:
        raise click.ClickException(str(exc))


# ---------------------------------------------------------------------------
# Routes — dashboard
# ---------------------------------------------------------------------------

@bp.route('/')
@login_required
def index():
    db = get_db()
    stats = {
        'services': db.execute('SELECT COUNT(*) AS count FROM services').fetchone()['count'],
        'attempts': db.execute('SELECT COUNT(*) AS count FROM attempts').fetchone()['count'],
        'whitelist': db.execute('SELECT COUNT(*) AS count FROM whitelist_entries WHERE enabled = 1').fetchone()['count'],
    }
    return render_template('index.html', stats=stats)


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

@bp.route('/services', methods=['GET', 'POST'])
@login_required
def services():
    db = get_db()

    if request.method == 'POST':
        _check_csrf()
        name        = request.form['name'].strip()
        ports_raw   = request.form['ports_raw'].strip()
        protocol    = request.form['protocol'].strip() or 'tcp'
        description = request.form['description'].strip()

        error = None
        port = None
        parsed_ports = []

        if not name:
            error = 'Имя сервиса обязательно.'
        elif not ports_raw:
            error = 'Укажите хотя бы один порт.'
        else:
            parsed_ports = parse_ports_raw(ports_raw)
            if not parsed_ports:
                error = 'Не удалось распознать порты. Примеры: 8080 или 80, 443 или 8000-8100'
            else:
                port = parsed_ports[0]

        if error is None:
            existing_service = db.execute('SELECT id FROM services WHERE port = ?', (port,)).fetchone()
            if existing_service is not None:
                error = f'Порт {port} уже занят другим сервисом.'

        if error is None:
            try:
                db.execute(
                    'INSERT INTO services (name, port, ports_raw, protocol, description) VALUES (?, ?, ?, ?, ?)',
                    (name, port, ports_raw, protocol, description)
                )
                db.execute(
                    'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                    ('create', 'service', f'{name}:{ports_raw}', 'Сервис добавлен через веб-форму')
                )
                db.commit()
                flash(f'Сервис "{name}" успешно добавлен ({len(parsed_ports)} портов).', 'success')
                return redirect(url_for('main.services'))
            except sqlite3.IntegrityError:
                flash(f'Не удалось добавить сервис: порт {port} уже существует.', 'error')
        else:
            flash(error, 'error')

    rows = db.execute('SELECT * FROM services ORDER BY port').fetchall()
    return render_template('services.html', services=rows)


@bp.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    db = get_db()
    service = db.execute('SELECT * FROM services WHERE id = ?', (service_id,)).fetchone()
    if service is None:
        flash('Сервис не найден.', 'error')
        return redirect(url_for('main.services'))

    if request.method == 'POST':
        _check_csrf()
        name        = request.form['name'].strip()
        ports_raw   = request.form['ports_raw'].strip()
        protocol    = request.form['protocol'].strip() or 'tcp'
        description = request.form['description'].strip()

        error = None
        parsed_ports = []

        if not name:
            error = 'Имя сервиса обязательно.'
        elif not ports_raw:
            error = 'Укажите хотя бы один порт.'
        else:
            parsed_ports = parse_ports_raw(ports_raw)
            if not parsed_ports:
                error = 'Не удалось распознать порты.'

        if error is None:
            port = parsed_ports[0]
            dup = db.execute('SELECT id FROM services WHERE port = ? AND id != ?', (port, service_id)).fetchone()
            if dup:
                error = f'Порт {port} уже занят другим сервисом.'

        if error is None:
            db.execute(
                'UPDATE services SET name=?, port=?, ports_raw=?, protocol=?, description=? WHERE id=?',
                (name, parsed_ports[0], ports_raw, protocol, description, service_id)
            )
            db.execute(
                'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                ('update', 'service', f'{name}:{ports_raw}', 'Сервис изменён')
            )
            db.commit()
            flash(f'Сервис "{name}" обновлён.', 'success')
            return redirect(url_for('main.services'))

        flash(error, 'error')
        service = {'id': service_id, 'name': name, 'ports_raw': ports_raw,
                   'protocol': protocol, 'description': description}

    return render_template('service_edit.html', service=service)


@bp.route('/services/<int:service_id>/delete', methods=['POST'])
@login_required
def delete_service(service_id):
    _check_csrf()
    db = get_db()
    service = db.execute('SELECT * FROM services WHERE id = ?', (service_id,)).fetchone()
    if service is None:
        flash('Сервис не найден.', 'error')
        return redirect(url_for('main.services'))

    db.execute('DELETE FROM services WHERE id = ?', (service_id,))
    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('delete', 'service', f"{service['name']}:{service['port']}", 'Сервис удалён')
    )
    db.commit()
    flash(f'Сервис "{service["name"]}" удалён.', 'success')
    return redirect(url_for('main.services'))


# ---------------------------------------------------------------------------
# Attempts / log import
# ---------------------------------------------------------------------------

@bp.route('/attempts/import-log', methods=['POST'])
@login_required
def import_attempts_from_log():
    _check_csrf()
    db = get_db()
    log_text = ''
    source = request.form.get('log_source', 'text')

    if source == 'file':
        log_path_raw = request.form.get('log_path', '').strip()
        if not log_path_raw:
            flash('Укажите путь к файлу лога.', 'error')
            return redirect(url_for('main.attempts'))
        try:
            log_text = Path(log_path_raw).read_text(encoding='utf-8', errors='replace')
        except Exception as exc:
            flash(f'Не удалось прочитать файл: {exc}', 'error')
            return redirect(url_for('main.attempts'))
    elif source == 'journal':
        try:
            result = subprocess.run(
                ['sudo', '-n', 'journalctl', '-k', '--no-pager', '-n', '5000', '--output=short-precise'],
                capture_output=True, text=True, timeout=15
            )
            log_text = result.stdout
        except Exception as exc:
            flash(f'Не удалось получить journald: {exc}', 'error')
            return redirect(url_for('main.attempts'))
    else:
        log_text = request.form.get('log_text', '')

    services_by_port = {}
    for row in db.execute('SELECT port, ports_raw, name FROM services').fetchall():
        ports_raw_val = row['ports_raw'] or str(row['port'])
        for p in parse_ports_raw(ports_raw_val) or [row['port']]:
            services_by_port[p] = row['name']

    added = 0
    for line in log_text.splitlines():
        # parse_log_line распознаёт события UFW ([UFW BLOCK/...]) и legacy BUTLER.
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip   = parsed['ip']
        port = parsed['port']
        service_name = services_by_port.get(port, f'port-{port}')

        existing = db.execute(
            'SELECT id, attempts_count FROM attempts WHERE ip_address = ? AND port = ?',
            (ip, port)
        ).fetchone()

        if existing:
            db.execute(
                'UPDATE attempts SET attempts_count = attempts_count + 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                (existing['id'],)
            )
        else:
            db.execute(
                'INSERT INTO attempts (ip_address, service_name, port, status) VALUES (?, ?, ?, ?)',
                (ip, service_name, port, 'new')
            )
            added += 1

    db.commit()
    flash(f'Импортировано новых записей: {added}.', 'success')
    return redirect(url_for('main.attempts'))


@bp.route('/attempts/<int:attempt_id>/allow', methods=['POST'])
@login_required
def allow_attempt(attempt_id):
    _check_csrf()
    db = get_db()
    row = db.execute('SELECT * FROM attempts WHERE id = ?', (attempt_id,)).fetchone()
    if row is None:
        flash('Попытка не найдена.', 'error')
        return redirect(url_for('main.attempts'))

    ip = str(ipaddress.ip_network(row['ip_address'], strict=False))
    exists = db.execute(
        'SELECT id FROM whitelist_entries WHERE ip_address = ? AND enabled = 1', (ip,)
    ).fetchone()
    if exists:
        flash(f'IP {ip} уже в белом списке.', 'error')
        return redirect(url_for('main.attempts'))

    db.execute('INSERT INTO whitelist_entries (ip_address, comment) VALUES (?, ?)',
               (ip, f'Добавлен из попыток (порт {row["port"]})'))
    db.execute('UPDATE attempts SET status = ? WHERE id = ?', ('allowed', attempt_id))
    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('allow', 'ip', ip, f'Разрешён из попыток, порт {row["port"]}')
    )
    db.commit()
    flash(f'IP {ip} добавлен в белый список.', 'success')
    return redirect(url_for('main.attempts'))


@bp.route('/attempts')
@login_required
def attempts():
    db = get_db()
    rows = db.execute('SELECT * FROM attempts ORDER BY last_seen DESC, id DESC').fetchall()

    ip_labels = {}
    def _norm_ip_key(raw):
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return str(net.network_address) if net.prefixlen == 32 else str(net)
        except ValueError:
            return raw

    for r in db.execute('SELECT ip_address, owner_name, comment FROM whitelist_entries WHERE enabled = 1').fetchall():
        label = r['owner_name'] or r['comment'] or ''
        if label:
            ip_labels[_norm_ip_key(r['ip_address'])] = ('whitelist', label)

    return render_template('attempts.html', attempts=rows, ip_labels=ip_labels)


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------

@bp.route('/whitelist', methods=['GET', 'POST'])
@login_required
def whitelist():
    db = get_db()

    if request.method == 'POST':
        _check_csrf()
        ip_address_raw = request.form['ip_address'].strip()
        owner_name     = request.form['owner_name'].strip()
        comment        = request.form['comment'].strip()

        error = None
        normalized_ip = None

        if not ip_address_raw:
            error = 'IP-адрес обязателен.'
        else:
            normalized_ip = validate_ip_address(ip_address_raw)
            if normalized_ip is None:
                error = 'Укажите корректный IPv4 или IPv6 адрес.'

        if error is None:
            existing_entry = db.execute(
                'SELECT id FROM whitelist_entries WHERE ip_address = ? AND enabled = 1',
                (normalized_ip,)
            ).fetchone()
            if existing_entry is not None:
                error = f'IP-адрес {normalized_ip} уже есть в белом списке.'

        if error is None:
            try:
                db.execute(
                    'INSERT INTO whitelist_entries (ip_address, owner_name, comment) VALUES (?, ?, ?)',
                    (normalized_ip, owner_name, comment)
                )
                db.execute(
                    'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                    ('allow', 'ip', normalized_ip, comment or 'IP добавлен в белый список')
                )
                db.commit()
                flash(f'IP {normalized_ip} добавлен в белый список.', 'success')
                return redirect(url_for('main.whitelist'))
            except sqlite3.IntegrityError:
                flash(f'Не удалось добавить IP {normalized_ip} в белый список.', 'error')
        else:
            flash(error, 'error')

    rows = db.execute(
        'SELECT * FROM whitelist_entries WHERE enabled = 1 ORDER BY created_at DESC, id DESC'
    ).fetchall()
    return render_template('whitelist.html', entries=rows)


@bp.route('/whitelist/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_whitelist_entry(entry_id):
    _check_csrf()
    db = get_db()
    entry = db.execute(
        'SELECT * FROM whitelist_entries WHERE id = ? AND enabled = 1', (entry_id,)
    ).fetchone()
    if entry is None:
        flash('Запись белого списка не найдена.', 'error')
        return redirect(url_for('main.whitelist'))

    db.execute('UPDATE whitelist_entries SET enabled = 0 WHERE id = ?', (entry_id,))
    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('delete', 'whitelist', entry['ip_address'], 'Запись отключена в белом списке')
    )
    db.commit()
    flash(f'IP {entry["ip_address"]} удалён из белого списка.', 'success')
    return redirect(url_for('main.whitelist'))


@bp.route('/whitelist/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_whitelist_entry(entry_id):
    db = get_db()
    entry = db.execute(
        'SELECT * FROM whitelist_entries WHERE id = ? AND enabled = 1', (entry_id,)
    ).fetchone()
    if entry is None:
        flash('Запись белого списка не найдена.', 'error')
        return redirect(url_for('main.whitelist'))

    if request.method == 'POST':
        _check_csrf()
        ip_address_raw = request.form['ip_address'].strip()
        owner_name     = request.form['owner_name'].strip()
        comment        = request.form['comment'].strip()

        error = None
        normalized_ip = None

        if not ip_address_raw:
            error = 'IP-адрес обязателен.'
        else:
            normalized_ip = validate_ip_address(ip_address_raw)
            if normalized_ip is None:
                error = 'Укажите корректный IPv4 или IPv6 адрес.'

        if error is None:
            existing_entry = db.execute(
                'SELECT id FROM whitelist_entries WHERE ip_address = ? AND enabled = 1 AND id != ?',
                (normalized_ip, entry_id)
            ).fetchone()
            if existing_entry is not None:
                error = f'IP-адрес {normalized_ip} уже есть в белом списке.'

        if error is None:
            db.execute(
                'UPDATE whitelist_entries SET ip_address = ?, owner_name = ?, comment = ? WHERE id = ?',
                (normalized_ip, owner_name, comment, entry_id)
            )
            db.execute(
                'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                ('update', 'whitelist', normalized_ip, 'Запись белого списка изменена')
            )
            db.commit()
            flash(f'Запись {normalized_ip} обновлена.', 'success')
            return redirect(url_for('main.whitelist'))

        flash(error, 'error')
        entry = {'id': entry_id, 'ip_address': ip_address_raw,
                 'owner_name': owner_name, 'comment': comment}

    return render_template('whitelist_edit.html', entry=entry)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@bp.route('/audit-log')
@login_required
def audit_log():
    db = get_db()
    rows = db.execute('SELECT * FROM audit_log ORDER BY created_at DESC, id DESC').fetchall()
    return render_template('audit_log.html', entries=rows)


# ---------------------------------------------------------------------------
# Conntrack helpers
# ---------------------------------------------------------------------------

def _conntrack_drop_ip(ip):
    try:
        subprocess.run(['sudo', '-n', 'conntrack', '-D', '-s', ip],
                       capture_output=True, text=True, timeout=10)
        return True, None
    except Exception as exc:
        return False, str(exc)


def _conntrack_drop_port(port, proto='tcp'):
    try:
        subprocess.run(['sudo', '-n', 'conntrack', '-D', '-p', proto, '--dport', str(port)],
                       capture_output=True, text=True, timeout=10)
        return True, None
    except Exception as exc:
        return False, str(exc)


@bp.route('/conntrack/drop-ips', methods=['POST'])
@login_required
def conntrack_drop_ips():
    _check_csrf()
    db = get_db()
    drop_all = request.form.get('drop_all') == '1'

    if drop_all:
        rows = db.execute(
            'SELECT ip_address FROM whitelist_entries WHERE enabled = 1'
        ).fetchall()
        ips = [r['ip_address'] for r in rows]
    else:
        ips = request.form.getlist('ip_address')

    if not ips:
        flash('Не выбран ни один IP-адрес.', 'error')
        return redirect(request.referrer or url_for('main.whitelist'))

    ok_count = 0
    for ip in ips:
        ok, err = _conntrack_drop_ip(ip)
        if ok:
            ok_count += 1
        else:
            flash(f'Ошибка при сбросе {ip}: {err}', 'error')

    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('conntrack_drop', 'ip', ', '.join(ips), f'Сброшено соединений: {ok_count}')
    )
    db.commit()
    flash(f'Соединения сброшены для {ok_count} из {len(ips)} адресов.', 'success')
    return redirect(request.referrer or url_for('main.whitelist'))


@bp.route('/conntrack/drop-ports', methods=['POST'])
@login_required
def conntrack_drop_ports():
    _check_csrf()
    db = get_db()
    drop_all = request.form.get('drop_all') == '1'

    if drop_all:
        rows = db.execute('SELECT port, ports_raw, protocol FROM services').fetchall()
    else:
        raw = request.form.getlist('port')
        if raw:
            placeholders = ','.join(['?'] * len(raw))
            rows = db.execute(
                f'SELECT port, ports_raw, protocol FROM services WHERE port IN ({placeholders})', raw
            ).fetchall()
        else:
            rows = []

    ports = []
    for r in rows:
        proto = r['protocol'] or 'tcp'
        ports_raw_val = r['ports_raw'] or str(r['port'])
        expanded = parse_ports_raw(ports_raw_val) or [r['port']]
        for p in expanded:
            ports.append((p, proto))

    if not ports:
        flash('Не выбран ни один порт.', 'error')
        return redirect(url_for('main.services'))

    ok_count = 0
    for port, proto in ports:
        ok, err = _conntrack_drop_port(port, proto or 'tcp')
        if ok:
            ok_count += 1
        else:
            flash(f'Ошибка при сбросе порта {port}: {err}', 'error')

    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('conntrack_drop', 'port', ', '.join(str(p[0]) for p in ports), f'Сброшено: {ok_count}')
    )
    db.commit()
    flash(f'Соединения сброшены для {ok_count} из {len(ports)} портов.', 'success')
    return redirect(url_for('main.services'))


# ---------------------------------------------------------------------------
# Firewall apply / reset
# ---------------------------------------------------------------------------

@bp.route('/firewall', methods=['GET'])
@login_required
def firewall():
    rules, mode, skipped = fw.build_rules()
    return render_template(
        'firewall.html',
        rules=rules,
        mode=mode,
        skipped=skipped,
    )


@bp.route('/firewall/export', methods=['POST'])
@login_required
def export_firewall():
    _check_csrf()
    generated_file = fw.write_generated_rules_file()
    flash(f'Файл правил сохранён: {generated_file}', 'success')
    return redirect(url_for('main.firewall'))


@bp.route('/firewall/apply', methods=['POST'])
@login_required
def firewall_apply():
    _check_csrf()
    confirm = request.form.get('confirm_apply')
    if confirm != 'yes':
        flash('Применение отменено: не подтверждено.', 'error')
        return redirect(url_for('main.firewall'))
    try:
        generated_file, target_file, backup_file = fw.apply_firewall_rules()
        msg = 'Правила применены.'
        if target_file:
            msg += f' Target: {target_file}.'
        if backup_file:
            msg += f' Backup: {backup_file}.'
        flash(msg, 'success')
    except Exception as exc:
        flash(str(exc), 'error')
    return redirect(url_for('main.firewall'))


@bp.route('/firewall/reset', methods=['POST'])
@login_required
def firewall_reset():
    _check_csrf()
    confirm = request.form.get('confirm_reset')
    if confirm != 'yes':
        flash('Сброс отменён: не подтверждён.', 'error')
        return redirect(url_for('main.firewall'))
    try:
        target_file, backup_file = fw.reset_firewall_rules()
        msg = 'Butler-правила сброшены.'
        if target_file:
            msg += f' Target: {target_file}.'
        if backup_file:
            msg += f' Backup: {backup_file}.'
        flash(msg, 'success')
    except Exception as exc:
        flash(str(exc), 'error')
    return redirect(url_for('main.firewall'))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if check_auth(username, password):
            session.clear()
            session['authenticated'] = True
            session['username'] = username
            # Регенерируем CSRF-токен после входа (защита от session fixation).
            session['csrf_token'] = secrets.token_hex(16)
            flash('Вы успешно вошли в систему.', 'success')
            return redirect(url_for('main.index'))
        flash('Неверный логин или пароль.', 'error')

    return render_template('login.html')


@bp.route('/logout', methods=['POST'])
def logout():
    _check_csrf()
    session.clear()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('main.login'))
