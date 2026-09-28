"""
Тесты генерации UFW-правил и защиты критичных портов (чек-лист §6, §7).
"""
from conftest import post


def add_whitelist(client, ip):
    post(client, '/whitelist', data={'ip_address': ip, 'owner_name': '', 'comment': ''},
         follow_redirects=True)


def add_service(client, name, ports_raw, protocol='tcp'):
    post(client, '/services', data={'name': name, 'ports_raw': ports_raw,
                                     'protocol': protocol, 'description': ''},
         follow_redirects=True)


# ──────────────────────────────────────────────
# Страница firewall
# ──────────────────────────────────────────────

def test_firewall_page_loads(auth_client):
    r = auth_client.get('/firewall')
    assert r.status_code == 200


def test_mode_switcher_removed(auth_client):
    r = auth_client.get('/firewall')
    assert r.status_code == 200
    assert b'firewall-mode' not in r.data
    r2 = post(auth_client, '/settings/firewall-mode', data={'mode': 'blacklist'})
    assert r2.status_code == 404


# ──────────────────────────────────────────────
# Генерация UFW-правил
# ──────────────────────────────────────────────

def test_build_rules_whitelist_mode(auth_client, app):
    """В whitelist-режиме allow для белого IP + deny на порт."""
    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')

    with app.app_context():
        from app.firewall import build_rules
        rules, mode, skipped = build_rules()

    assert mode == 'whitelist'
    assert '192.168.1.1' in rules
    assert 'allow from 192.168.1.1' in rules
    assert 'deny 80/tcp' in rules
    assert 'deny in from any to any' not in rules


def test_unlisted_port_has_no_allow(auth_client, app):
    """Порт Docker/сервиса, которого нет в списке, не получает allow — только общий deny."""
    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '9999' not in rules
    assert 'deny in from any to any' not in rules


def test_build_rules_multiport(auth_client, app):
    """7.2 — мультипорт через запятую раскрывается в правилах."""
    add_service(auth_client, 'MULTI', '80,443')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '80/tcp' in rules
    assert '443/tcp' in rules


def test_build_rules_port_range(auth_client, app):
    """7.3 — диапазон портов раскрывается корректно."""
    add_service(auth_client, 'RANGE', '8000-8010')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    for port in range(8000, 8011):
        assert f'{port}/tcp' in rules


def test_build_rules_subnet_in_whitelist(auth_client, app):
    """7.4 — CIDR-подсеть корректно попадает в правила."""
    add_whitelist(auth_client, '188.243.183.0/24')
    add_service(auth_client, 'TEST', '80')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, skipped = build_rules()

    assert '188.243.183.0/24' in rules
    assert skipped == []


def test_udp_service_uses_udp_proto(auth_client, app):
    """UDP-сервис даёт правило с proto udp, а не tcp."""
    add_service(auth_client, 'DNS', '53', protocol='udp')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '53/udp' in rules
    assert '53/tcp' not in rules


def test_both_protocol_appears_in_both(auth_client, app):
    """Протокол 'both' даёт правило и для tcp, и для udp."""
    add_service(auth_client, 'BOTH', '1194', protocol='both')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '1194/tcp' in rules
    assert '1194/udp' in rules


# ──────────────────────────────────────────────
# IPv6
# ──────────────────────────────────────────────

def test_build_rules_ipv6_whitelist(auth_client, app):
    """IPv6-адрес из белого списка попадает в правила."""
    add_whitelist(auth_client, '2001:db8::1')
    add_service(auth_client, 'V6WEB', '80')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, skipped = build_rules()

    assert '2001:db8::1' in rules
    assert skipped == []


def test_build_rules_ipv6_subnet(auth_client, app):
    """IPv6-подсеть из белого списка попадает в правила."""
    add_whitelist(auth_client, '2001:db8::/32')
    add_service(auth_client, 'V6WEB2', '443')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, skipped = build_rules()

    assert '2001:db8::/32' in rules
    assert skipped == []


# ──────────────────────────────────────────────
# Защита SSH и порта панели от deny
# ──────────────────────────────────────────────

def test_ssh_never_denied(auth_client, app):
    """SSH(22) всегда allow и никогда не появляется в deny-правилах сервисов."""
    add_service(auth_client, 'SSHSVC', '22')
    add_whitelist(auth_client, '192.168.1.1')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert 'allow 22/tcp' in rules
    assert 'deny 22/tcp' not in rules


def test_butler_port_never_denied(auth_client, app):
    """Порт панели Butler (5050) всегда allow и не блокируется deny."""
    add_service(auth_client, 'PANEL', '5050')
    add_whitelist(auth_client, '192.168.1.1')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert 'allow 5050/tcp' in rules
    assert 'deny 5050/tcp' not in rules


def test_firewall_preview_endpoint(auth_client):
    """Страница /firewall возвращает предпросмотр правил."""
    r = auth_client.get('/firewall')
    assert r.status_code == 200
    assert b'ufw' in r.data.lower() or b'butler' in r.data.lower()


# ──────────────────────────────
# Вызов ufw через sudo -n (главный фикс "You need to be root")
# ──────────────────────────────

def test_ufw_cmd_prefixed_with_sudo():
    """_ufw_cmd обязан всегда начинаться с 'sudo -n' — ufw требует root."""
    from app.firewall import _ufw_cmd, _UFW
    cmd = _ufw_cmd('status')
    assert cmd[0] == 'sudo'
    assert cmd[1] == '-n'
    assert cmd[2] == _UFW
    assert cmd[3] == 'status'


def test_rule_commands_all_use_sudo(auth_client, app):
    """Все сгенерированные команды ufw вызываются через sudo -n."""
    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')

    with app.app_context():
        from app.firewall import _rule_commands
        commands, _mode, _skipped = _rule_commands()

    assert commands, 'ожидались правила'
    for cmd in commands:
        assert cmd[:2] == ['sudo', '-n'], f'команда без sudo -n: {cmd}'


def test_ensure_enabled_sets_default_policies(auth_client, app, monkeypatch):
    """_ensure_enabled_and_protected задаёт default deny incoming / allow outgoing
    и разрешает SSH + порт панели, всё через sudo -n."""
    import app.firewall as fw

    called = []

    def fake_run(command, error_prefix, timeout=15):
        called.append(command)
        class R:  # заглушка результата
            returncode = 0
            stdout = ''
            stderr = ''
        return R()

    def fake_try(command, timeout=15):
        # имитируем активный UFW, чтобы enable не вызывался
        return True, 'Status: active'

    monkeypatch.setattr(fw, 'run_command', fake_run)
    monkeypatch.setattr(fw, '_try_command', fake_try)

    with app.app_context():
        fw._ensure_enabled_and_protected()

    # Все run_command-вызовы идут через sudo -n
    for cmd in called:
        assert cmd[:2] == ['sudo', '-n'], f'команда без sudo -n: {cmd}'

    flat = [' '.join(c[2:]) for c in called]
    joined = '\n'.join(flat)
    # SSH и порт панели разрешены
    assert any('allow 22/tcp' in f for f in flat)
    assert any('allow 5050/tcp' in f for f in flat)
    # Дефолтные политики заданы
    assert 'default deny incoming' in joined
    assert 'default allow outgoing' in joined


def test_with_insert_prefixes_ufw_insert():
    """Правила должны вставляться в позицию 1, иначе чужой LAN-allow их перекрывает."""
    from app.firewall import _ufw_cmd, _with_insert
    cmd = _ufw_cmd('deny', '80/tcp', 'comment', 'butler')
    inserted = _with_insert(cmd)
    assert inserted[3:5] == ['insert', '1']
    assert inserted[5:] == cmd[3:]


def test_apply_inserts_rules_at_top_in_reverse(auth_client, app, monkeypatch):
    """apply не вставляет общий deny первым — SSH не режется на середине apply."""
    import app.firewall as fw

    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')

    applied = []

    def fake_run(command, error_prefix, timeout=15):
        applied.append(command)
        class R:
            returncode = 0
            stdout = ''
            stderr = ''
        return R()

    monkeypatch.setattr(fw, 'run_command', fake_run)
    monkeypatch.setattr(fw, '_ensure_enabled_and_protected', lambda: None)
    monkeypatch.setattr(fw, '_delete_butler_rules', lambda: 0)
    monkeypatch.setattr(fw, '_drop_service_connections', lambda: None)
    monkeypatch.setattr(fw, '_apply_docker_isolation', lambda: None)
    monkeypatch.setattr(fw, 'write_generated_rules_file', lambda: None)

    with app.app_context():
        fw.apply_firewall_rules()

    final_order = list(reversed(applied))
    assert final_order[0][5:8] == ['allow', 'from', '192.168.1.1']
    assert final_order[-1][5:7] == ['deny', '80/tcp']
    positions = [int(c[4]) for c in applied if c[3] == 'insert']
    assert positions == [1] * len(positions)
    assert not any(c[5:11] == ['deny', 'in', 'from', 'any', 'to', 'any'] for c in applied)


def test_apply_deny_port_after_whitelist_allow(auth_client, app, monkeypatch):
    """deny 80/tcp не должен вставляться insert 1 поверх allow from IP port 80."""
    import app.firewall as fw

    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')

    applied = []

    def fake_run(command, error_prefix, timeout=15):
        applied.append(command)
        class R:
            returncode = 0
            stdout = ''
            stderr = ''
        return R()

    monkeypatch.setattr(fw, 'run_command', fake_run)
    monkeypatch.setattr(fw, '_ensure_enabled_and_protected', lambda: None)
    monkeypatch.setattr(fw, '_delete_butler_rules', lambda: 0)
    monkeypatch.setattr(fw, '_drop_service_connections', lambda: None)
    monkeypatch.setattr(fw, '_apply_docker_isolation', lambda: None)
    monkeypatch.setattr(fw, 'write_generated_rules_file', lambda: None)

    with app.app_context():
        fw.apply_firewall_rules()

    def idx(predicate):
        for i, c in enumerate(applied):
            if predicate(c):
                return i
        return -1

    i_allow = idx(lambda c: '192.168.1.1' in c and 'port' in c and '80' in c)
    i_deny80 = idx(lambda c: len(c) > 6 and c[5:7] == ['deny', '80/tcp'])
    assert i_allow >= 0 and i_deny80 >= 0
    assert i_deny80 < i_allow, 'deny применяется раньше, чтобы allow оказался выше после insert 1'


def test_list_broad_allow_rules_parses_lan_allow(monkeypatch):
    import app.firewall as fw

    sample = """
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   ALLOW IN    192.168.100.0/24           # LAN home
[ 2] Anywhere on wlo1           ALLOW IN    192.168.100.0/24
[ 3] 80/tcp                     ALLOW IN    192.168.100.3              # butler
[ 4] 80/tcp                     DENY IN     Anywhere                   # butler
"""
    monkeypatch.setattr(fw, '_try_command', lambda *a, **k: (True, sample))
    found = fw.list_broad_allow_rules()
    assert len(found) == 2
    assert any('192.168.100.0/24' in line for line in found)
    assert all('# butler' not in line for line in found)


def test_ssh_and_panel_allowed_before_default_deny(auth_client, app, monkeypatch):
    """Защита от self-lockout: allow SSH/панели ИДЁТ ДО default deny incoming."""
    import app.firewall as fw
    order = []

    def fake_run(command, error_prefix, timeout=15):
        order.append(' '.join(command[2:]))
        class R:
            returncode = 0; stdout = ''; stderr = ''
        return R()

    monkeypatch.setattr(fw, 'run_command', fake_run)
    monkeypatch.setattr(fw, '_try_command', lambda c, timeout=15: (True, 'Status: active'))

    with app.app_context():
        fw._ensure_enabled_and_protected()

    idx_allow_ssh = next(i for i, c in enumerate(order) if 'allow 22/tcp' in c)
    idx_deny_default = next(i for i, c in enumerate(order) if 'default deny incoming' in c)
    assert idx_allow_ssh < idx_deny_default, 'аllow SSH должен идти до default deny'


def test_docker_isolation_skips_without_docker(auth_client, app, monkeypatch):
    import app.firewall as fw
    import app.ufw_docker as ud

    monkeypatch.setattr(fw, '_try_command', lambda cmd, timeout=15: (False, ''))
    monkeypatch.setattr(fw.Path, 'exists', lambda self: False)
    monkeypatch.setattr(ud, 'sync_docker_whitelist_from_db', lambda: (_ for _ in ()).throw(AssertionError('sync')))

    with app.app_context():
        fw._apply_docker_isolation()


def test_apply_calls_ufw_docker_sync(auth_client, app, monkeypatch):
    import app.firewall as fw
    import app.ufw_docker as ud

    calls = []
    monkeypatch.setattr(fw, '_try_command', lambda cmd, timeout=15: (True, ''))
    monkeypatch.setattr(ud, 'sync_docker_whitelist_from_db', lambda: calls.append('sync'))

    with app.app_context():
        fw._apply_docker_isolation()

    assert calls == ['sync']


def test_ufw_docker_sync_adds_route_rules(auth_client, app, monkeypatch, tmp_path):
    import app.ufw_docker as ud

    bin_path = tmp_path / 'ufw-docker'
    bin_path.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
    bin_path.chmod(0o755)
    monkeypatch.setattr(ud, 'ufw_docker_bin', lambda: bin_path)
    monkeypatch.setattr(ud, '_ufw_docker_block_present', lambda: True)
    monkeypatch.setattr(ud, 'delete_butler_docker_routes', lambda: 0)
    monkeypatch.setattr(
        ud,
        'iter_docker_publishes',
        lambda: [ud.DockerPublish(8080, 80, 'tcp', '172.17.0.2', 'web')],
    )

    applied = []

    def fake_run(cmd, prefix, timeout=15):
        applied.append(cmd)

    monkeypatch.setattr(ud, 'run_command', fake_run)
    monkeypatch.setattr(ud, '_try_command', lambda cmd, timeout=15: (True, ''))

    add_service(auth_client, 'WEB', '8080')
    add_whitelist(auth_client, '10.0.0.5')

    with app.app_context():
        ud.sync_docker_whitelist_from_db()

    assert ['sudo', '-n', str(bin_path), 'install', '--docker-subnets'] in applied
    route = [c for c in applied if 'route' in c and 'allow' in c]
    assert route
    assert '10.0.0.5' in route[0] and '172.17.0.2' in route[0]
    assert 'butler-docker' in ' '.join(route[0])


def test_rule_commands_deny_unmanaged_docker_publish(auth_client, app, monkeypatch):
    """Опубликованный Docker-порт без сервиса в Butler попадает в deny."""
    import app.firewall as fw

    monkeypatch.setattr(
        fw, '_docker_published_host_ports', lambda: {8020, 9000},
    )
    add_service(auth_client, 'WEB', '80')

    with app.app_context():
        commands, _mode, _skipped = fw._rule_commands()

    joined = [' '.join(c[3:]) for c in commands]
    assert any('deny 8020/tcp' in s for s in joined)
    assert any('deny 9000/tcp' in s for s in joined)
