"""Интеграция Butler с ufw-docker (Docker + UFW).

Хост-сервисы — обычные правила UFW из firewall.py.
Опубликованные порты Docker — блок ufw-docker в after.rules + route allow
только с IP белого списка (не ``ufw-docker allow``, который открывает всем).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .db import get_db
from .firewall import _collect_ips, _iter_service_specs, _protected_ports, _try_command, _ufw_cmd, run_command

BUTLER_DOCKER_TAG = 'butler-docker'


def _inner_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def ufw_docker_bin() -> Path:
    return _inner_dir() / 'bin' / 'ufw-docker'


@dataclass(frozen=True)
class DockerPublish:
    host_port: int
    container_port: int
    proto: str
    container_ip: str
    container_name: str


def iter_docker_publishes() -> list[DockerPublish]:
    docker = shutil.which('docker') or '/usr/bin/docker'
    ok, out = _try_command([docker, 'ps', '-q'], timeout=30)
    if not ok:
        raise RuntimeError('Не удалось получить список контейнеров Docker: ' + out)
    if not out.strip():
        return []
    inspected = run_command([docker, 'inspect', *out.split()],
                            'Не удалось проверить контейнеры Docker:', timeout=30)
    result = set()
    for container in json.loads(inspected.stdout):
        settings = container.get('NetworkSettings') or {}
        addresses = [network.get('IPAddress') for network in
                     (settings.get('Networks') or {}).values() if network.get('IPAddress')]
        for key, binds in (settings.get('Ports') or {}).items():
            if not binds:
                continue
            if not addresses:
                raise RuntimeError('Не определён адрес опубликованного контейнера ' + container['Name'])
            port, proto = key.split('/')
            for bind in binds:
                result.add(DockerPublish(int(bind['HostPort']), int(port), proto,
                                         addresses[0], container['Name'].lstrip('/')))
    return sorted(result, key=lambda p: (p.host_port, p.proto, p.container_ip))


def _list_route_rule_numbers(tag: str) -> list[int]:
    ok, out = _try_command(_ufw_cmd('status', 'numbered'))
    if not ok:
        return []
    numbers = []
    for line in out.splitlines():
        if f'# {tag}' not in line and tag not in line:
            continue
        m = re.match(r'\s*\[\s*(\d+)\s*\]', line)
        if m:
            numbers.append(int(m.group(1)))
    return sorted(numbers, reverse=True)


def delete_butler_docker_routes() -> int:
    from .firewall import _delete_tagged_rules
    return _delete_tagged_rules(BUTLER_DOCKER_TAG)


def _ensure_ufw_docker_installed() -> None:
    bin_path = ufw_docker_bin()
    if not bin_path.is_file():
        raise RuntimeError(
            f'Не найден {bin_path}. Запустите ./install.sh на сервере (ставит ufw-docker из bundled/).'
        )
    cat = shutil.which('cat') or '/usr/bin/cat'
    before_ok, before = _try_command(['sudo', '-n', cat, '/etc/ufw/after.rules', '/etc/ufw/before.rules', '/etc/ufw/before6.rules'])
    run_command(
        # Default ufw-docker permits all RFC1918 source networks, including
        # this server's LAN.  Restrict its bypass to Docker's own networks so
        # external access is governed exclusively by Butler's route rules.
        ['sudo', '-n', str(bin_path), 'install', '--docker-subnets'],
        'ufw-docker install не выполнен (нужен sudo на скрипт и запись в /etc/ufw/after.rules):',
        timeout=120,
    )
    after_ok, after = _try_command(['sudo', '-n', cat, '/etc/ufw/after.rules', '/etc/ufw/before.rules', '/etc/ufw/before6.rules'])
    iptables = shutil.which('iptables') or '/usr/sbin/iptables'
    live_ok, live = _try_command(['sudo', '-n', iptables, '-S', 'DOCKER-USER'])
    if not (before_ok and after_ok and before == after and live_ok
            and '-j ufw-user-forward' in live):
        run_command(_ufw_cmd('reload'), 'Не удалось загрузить правила Docker:', timeout=60)


def sync_docker_whitelist_from_db() -> None:
    """ufw-docker install + ufw route allow только whitelist → контейнер."""
    _ensure_ufw_docker_installed()
    delete_butler_docker_routes()

    db = get_db()
    rows = db.execute(
        'SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address'
    ).fetchall()
    whitelist_ips, skipped = _collect_ips(rows)
    if skipped:
        raise ValueError('Некорректные адреса белого списка: ' + ', '.join(skipped))
    managed_specs = set(_iter_service_specs())
    protected = _protected_ports()

    for pub in iter_docker_publishes():
        if pub.host_port in protected:
            continue
        if (pub.host_port, pub.proto) not in managed_specs:
            continue
        for ip in whitelist_ips or ['any']:
            run_command(
                _ufw_cmd(
                    'route', 'allow', 'proto', pub.proto,
                    'from', ip, 'to', pub.container_ip, 'port', str(pub.container_port),
                    'comment', BUTLER_DOCKER_TAG,
                ),
                f'Не удалось ufw route allow Docker {pub.container_name} '
                f'{pub.host_port}→{pub.container_port} для {ip}:',
            )

    if not _ufw_docker_block_present():
        raise RuntimeError(
            'В /etc/ufw/after.rules нет блока «BEGIN UFW AND DOCKER» после ufw-docker install. '
            'Проверьте sudo и выполните: sudo .butler/bin/ufw-docker install && sudo ufw reload'
        )


def _ufw_docker_block_present() -> bool:
    after = Path('/etc/ufw/after.rules')
    if not after.is_file():
        return False
    cat = shutil.which('cat') or '/usr/bin/cat'
    ok, text = _try_command(['sudo', '-n', cat, str(after)], timeout=15)
    if not ok:
        return False
    return '# BEGIN UFW AND DOCKER' in text
