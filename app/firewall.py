"""Butler firewall backend — UFW only.

Butler управляет доступом к сервисам через UFW (Uncomplicated Firewall).

Стратегия применения правил — ИНКРЕМЕНТАЛЬНАЯ и ИДЕМПОТЕНТНАЯ:

  * Butler НИКОГДА не вызывает `ufw reset` и не выполняет `ufw disable/enable`
    во время применения правил. Это защищает от двух проблем прошлого прода:
      1. `ufw reset` на Astra Linux стирает /etc/sudoers.d/ → потеря sudo NOPASSWD.
      2. reset/disable рвёт активные соединения, включая текущую SSH-сессию.

  * Все правила Butler помечаются комментарием `butler` (ufw ... comment 'butler').
    При каждом apply Butler удаляет ТОЛЬКО свои прежние правила (по комментарию),
    затем добавляет актуальный набор. Чужие правила не трогаются.

  * SSH (порт 22) и порт веб-панели Butler защищаются отдельным `allow` и
    НИКОГДА не удаляются и не перекрываются deny-правилами.

Публичный API (используется routes.py):
    build_rules()                -> (rules_text, mode, skipped_list)
    write_generated_rules_file() -> generated_file_path
    apply_firewall_rules()       -> (generated_file, target_file_or_None, backup_file_or_None)
    reset_firewall_rules()       -> (target_file_or_None, backup_file_or_None)
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
from functools import wraps
from datetime import datetime
from pathlib import Path

from flask import current_app

from .db import get_db, parse_ports_raw

# Полный путь к ufw обязателен для совпадения с NOPASSWD в sudoers (Astra Linux).
_UFW = shutil.which('ufw') or '/usr/sbin/ufw'

# Комментарий-маркер, которым Butler помечает все свои правила.
BUTLER_TAG = 'butler'

# Порт SSH — защищаем всегда, никогда не закрываем (удалённые серверы).
SSH_PORT = 22


def _ufw_cmd(*args) -> list:
    """Собрать команду ufw с sudo -n.

    Сервис Butler работает под обычным пользователем, а ufw требует root.
    sudoers.sh выдаёт этому пользователю NOPASSWD на ufw, поэтому вызываем
    через `sudo -n` (без пароля, без запроса tty). Если процесс уже root —
    sudo просто выполнит команду напрямую без лишних вопросов.
    """
    return ['sudo', '-n', _UFW, *args]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_butler_port() -> int:
    """Порт, на котором слушает веб-панель Butler. Дефолт 5050, берётся из конфига/env."""
    try:
        return int(current_app.config.get('BUTLER_PORT',
                                           os.environ.get('BUTLER_PORT', 5050)))
    except (TypeError, ValueError):
        return 5050


def _protected_ports() -> set:
    """Порты, которые Butler никогда не блокирует и не перекрывает deny."""
    return {SSH_PORT, _get_butler_port()}


def run_command(command, error_prefix, timeout=15):
    """Выполнить команду, поднять RuntimeError при ненулевом коде возврата."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'{error_prefix}\nКоманда превысила timeout ({timeout}s).')
    if result.returncode != 0:
        raise RuntimeError(f'{error_prefix}\n' + (result.stderr.strip() or result.stdout.strip()))
    return result


def _try_command(command, timeout=15):
    """Выполнить команду, вернуть (ok: bool, output: str). Не поднимает исключение."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f'timeout ({timeout}s)'
    except (FileNotFoundError, OSError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, (result.stderr.strip() or result.stdout.strip())
    return True, result.stdout


def _collect_ips(rows):
    """Разобрать строки БД в список нормализованных IP/подсетей (v4 и v6).

    Возвращает (ip_list, invalid_list). Поддерживаются и IPv4, и IPv6.
    """
    result = []
    invalid = []
    for row in rows:
        raw = row['ip_address'].strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            # /32 (v4) и /128 (v6) — представляем как одиночный адрес.
            if net.prefixlen == net.max_prefixlen:
                result.append(str(net.network_address))
            else:
                result.append(str(net))
        except ValueError:
            invalid.append(raw)
    return result, invalid


# ---------------------------------------------------------------------------
# Правила: сборка списка UFW-команд из БД
# ---------------------------------------------------------------------------

def _iter_service_specs():
    """Итератор по (port:int, proto:str in {'tcp','udp'}) для всех сервисов."""
    db = get_db()
    services = db.execute(
        'SELECT port, ports_raw, protocol FROM services ORDER BY port'
    ).fetchall()
    protected = _protected_ports()
    for row in services:
        proto = (row['protocol'] or 'tcp').lower().strip()
        ports_raw = row['ports_raw'] or str(row['port'])
        expanded = parse_ports_raw(ports_raw) or [row['port']]
        protos = ['tcp', 'udp'] if proto == 'both' else [proto if proto in ('tcp', 'udp') else 'tcp']
        for port in sorted(set(expanded)):
            if port in protected:
                # SSH и порт панели никогда не трогаем сервисными правилами.
                continue
            for use_proto in protos:
                yield port, use_proto


def _rule_commands():
    """Построить список UFW-команд (списки argv) для применения из текущей БД.

    Только белый список: сервис доступен исключительно с IP из whitelist.
    Порт, который не добавлен как сервис (в том числе опубликованный Docker),
    закрывается общим deny — иначе чужой LAN-allow или default-дыры его пускают.

    Все правила снабжаются `comment 'butler'` для последующей идемпотентной чистки.
    Возвращает (commands: list[list[str]], mode: str, skipped: list[str]).
    """
    db = get_db()
    whitelist_rows = db.execute(
        'SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address'
    ).fetchall()
    whitelist_ips, skipped = _collect_ips(whitelist_rows)
    if skipped:
        raise ValueError('Некорректные адреса белого списка: ' + ', '.join(skipped))

    commands = []

    for port, proto in _iter_service_specs():
        if not whitelist_ips:
            commands.append(_ufw_cmd('allow', f'{port}/{proto}', 'comment', BUTLER_TAG))
            continue
        for ip in whitelist_ips:
            commands.append(
                _ufw_cmd('allow', 'from', ip, 'to', 'any', 'port', str(port),
                         'proto', proto, 'comment', BUTLER_TAG)
            )
        commands.append(_ufw_cmd('deny', f'{port}/{proto}', 'comment', BUTLER_TAG))

    # Не добавляем общий deny: default deny incoming закрывает незаявленные
    # сервисы, а общий deny выше SSH мог бы отрезать администратора при сбое.
    # Опубликованные Docker-порты закрывает ufw-docker ниже.
    return _supplement_unmanaged_docker_denies(commands), 'whitelist', skipped


def _docker_published_host_ports() -> set[int]:
    """Хост-порты из `docker ps` (0.0.0.0:8020->...). Без Docker — пусто."""
    docker = shutil.which('docker') or '/usr/bin/docker'
    ok, out = _try_command([docker, 'ps', '--format', '{{.Ports}}'], timeout=15)
    if not ok or not out:
        return set()
    ports: set[int] = set()
    for chunk in out.replace('\n', ',').split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.search(r':(\d+)->', chunk)
        if m:
            ports.add(int(m.group(1)))
    return ports


def _supplement_unmanaged_docker_denies(commands: list) -> list:
    """Добавить deny для опубликованных Docker-портов, не заведённых как сервис."""
    managed = {port for port, _ in _iter_service_specs()}
    protected = _protected_ports()
    extra: list = []
    for pub in sorted(_docker_published_host_ports()):
        if pub in managed or pub in protected:
            continue
        extra.append(_ufw_cmd('deny', f'{pub}/tcp', 'comment', BUTLER_TAG))
        extra.append(_ufw_cmd('deny', f'{pub}/udp', 'comment', BUTLER_TAG))
    return commands + extra


def _with_insert(cmd: list, position: int = 1) -> list:
    """sudo -n ufw allow ... → sudo -n ufw insert 1 allow ...

    Без insert новые правила попадают в КОНЕЦ user-цепочки. Тогда чужой
    `allow from 192.168.100.0/24 to any` срабатывает раньше butler-deny,
    и весь LAN проходит в сервис, хотя в белом списке один IP.
    """
    return [*cmd[:3], 'insert', str(position), *cmd[3:]]


def _ufw_args(cmd: list) -> list:
    """Аргументы ufw без префикса sudo -n <path>."""
    return cmd[3:]


def _is_global_inbound_deny(cmd: list) -> bool:
    """deny in from any to any — блокирует ВСЁ входящее, в т.ч. SSH."""
    args = _ufw_args(cmd)
    return (
        len(args) >= 6
        and args[0] == 'deny'
        and args[1] == 'in'
        and args[2] == 'from'
        and args[3] == 'any'
        and args[4] == 'to'
        and args[5] == 'any'
    )


def _apply_butler_ufw_commands(commands: list) -> None:
    """Применить правила: строгий порядок как в предпросмотре (первое совпадение).

    UFW на Astra не принимает ``insert N``, если правила с номером N ещё нет.
    Вставляем каждое правило в позицию 1, но обходим список с конца: итоговый
    порядок остаётся таким же, как в предпросмотре, а команда корректна даже
    для пустого UFW.
    """
    for cmd in reversed(_compact_rules(commands)):
        inserted = _with_insert(cmd, 1)
        run_command(inserted, f'Не удалось применить правило: {" ".join(inserted[1:])}')


def _compact_rules(commands):
    """UFW multiport accepts 15 ports; combine only identical access conditions."""
    groups = {}
    for command in commands:
        args = command[3:]
        if '/' in args[1]:
            port, proto = args[1].split('/')
            key = (args[0], 'any', proto)
        else:
            port = args[args.index('port') + 1]
            key = (args[0], args[args.index('from') + 1], args[args.index('proto') + 1])
        groups.setdefault(key, set()).add(int(port))
    result = []
    # All source-specific allows must precede their port denies.
    for (action, source, proto), ports in sorted(groups.items(), key=lambda item: item[0][0] != 'allow'):
        ports = sorted(ports)
        for offset in range(0, len(ports), 15):
            chunk = ','.join(map(str, ports[offset:offset + 15]))
            if source == 'any':
                result.append(_ufw_cmd(action, f'{chunk}/{proto}', 'comment', BUTLER_TAG))
            else:
                result.append(_ufw_cmd(action, 'from', source, 'to', 'any', 'port', chunk,
                                       'proto', proto, 'comment', BUTLER_TAG))
    return result


def _exclusive_apply(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        import fcntl
        path = Path(current_app.config['DATABASE']).resolve().with_suffix('.apply.lock')
        with path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Правила уже применяются. Дождитесь завершения.')
            try:
                return function(*args, **kwargs)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    return wrapped


def list_broad_allow_rules() -> list[str]:
    """Чужие UFW-правила вида «ALLOW from подсети/IP на Anywhere» (любой порт).

    Они перекрывают whitelist, если стоят выше deny. После apply Butler
    вставляет свои правила в позицию 1, но предупреждение всё равно полезно.
    """
    ok, out = _try_command(_ufw_cmd('status', 'numbered'))
    if not ok:
        return []
    found = []
    for line in out.splitlines():
        if f'# {BUTLER_TAG}' in line:
            continue
        # "[ 1] Anywhere  ALLOW IN  192.168.100.0/24"
        # "[ 2] Anywhere on wlo1  ALLOW IN  192.168.100.0/24"
        m = re.match(
            r'\s*\[\s*\d+\s*\]\s+(Anywhere(?:\s+on\s+\S+)?)\s+ALLOW IN\s+(\S+)',
            line,
        )
        if m:
            found.append(line.strip())
    return found


def _parse_ufw_numbered_rules() -> list[dict]:
    """Разобрать ``ufw status numbered`` в список правил по возрастанию номера."""
    ok, out = _try_command(_ufw_cmd('status', 'numbered'))
    if not ok:
        return []
    rules = []
    for line in out.splitlines():
        m = re.match(
            r'\s*\[\s*(\d+)\s*\]\s+(.+?)\s+(ALLOW|DENY|REJECT)\s+IN\s+(.+?)(?:\s+#\s*(.*))?$',
            line,
        )
        if not m:
            continue
        rules.append({
            'num': int(m.group(1)),
            'to': m.group(2).strip(),
            'action': m.group(3),
            'from': m.group(4).strip(),
            'comment': (m.group(5) or '').strip(),
            'raw': line.strip(),
        })
    return sorted(rules, key=lambda r: r['num'])


def _ufw_rule_matches(rule: dict, src_ip: str, port: int, proto: str) -> bool:
    """Грубая проверка: правило UFW относится к входящему src→port/proto."""
    to_field = rule['to']
    from_field = rule['from']
    if from_field not in ('Anywhere', 'Anywhere (v6)') and from_field != src_ip:
        try:
            net = ipaddress.ip_network(from_field, strict=False)
            if ipaddress.ip_address(src_ip) not in net:
                return False
        except ValueError:
            return False
    if to_field in ('Anywhere', 'Anywhere (v6)'):
        return True
    if f'{port}/{proto}' in to_field.replace(' ', ''):
        return True
    if to_field.startswith(f'{port}/'):
        return True
    return False


def diagnose_port_access(port: int, src_ip: str, proto: str = 'tcp') -> dict:
    """Почему с src_ip не открывается port — UFW, сервис в БД, listen, Docker."""
    proto = (proto or 'tcp').lower()
    lines: list[str] = []
    warnings: list[str] = []

    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        warnings.append(f'Некорректный IP клиента: {src_ip}')
        src_ip = src_ip.strip()

    db = get_db()
    svc_rows = db.execute(
        'SELECT name, port, ports_raw, protocol FROM services WHERE port = ? OR ports_raw LIKE ?',
        (port, f'%{port}%'),
    ).fetchall()
    managed_specs = list(_iter_service_specs())
    managed_ports = {p for p, _ in managed_specs}
    in_butler = port in managed_ports

    if not svc_rows:
        lines.append(f'В Butler нет сервиса с портом {port} — UFW закроет его (catch-all / Docker deny).')
    else:
        names = ', '.join(r['name'] for r in svc_rows)
        lines.append(f'Сервис в Butler: {names} (порт {port}).')

    wl_rows = db.execute(
        'SELECT ip_address FROM whitelist_entries WHERE enabled = 1'
    ).fetchall()
    wl_ips, _ = _collect_ips(wl_rows)
    on_whitelist = False
    for wip in wl_ips:
        try:
            net = ipaddress.ip_network(wip, strict=False)
            if ipaddress.ip_address(src_ip) in net:
                on_whitelist = True
                break
        except ValueError:
            if wip == src_ip:
                on_whitelist = True
                break
    if on_whitelist:
        lines.append(f'IP {src_ip} есть в белом списке.')
    else:
        warnings.append(f'IP {src_ip} НЕ в белом списке — доступ к сервисам Butler запрещён.')

    if in_butler and on_whitelist:
        expected = 'ALLOW (ожидается доступ)'
    elif in_butler:
        expected = 'DENY (нет в whitelist)'
    else:
        expected = 'DENY (порт не заведён как сервис)'
    lines.append(f'Ожидание UFW для {src_ip} → {port}/{proto}: {expected}')

    ufw_rules = _parse_ufw_numbered_rules()
    port_rules = [r for r in ufw_rules if _ufw_rule_matches(r, src_ip, port, proto)]
    first = None
    for r in ufw_rules:
        if _ufw_rule_matches(r, src_ip, port, proto):
            first = r
            break
    if not ufw_rules:
        warnings.append('Не удалось прочитать ufw status numbered (нет sudo?).')
    elif first:
        lines.append(
            f'Первое срабатывающее правило UFW: [{first["num"]}] {first["action"]} '
            f'({first["to"]} from {first["from"]}) {first["comment"]!r}'
        )
        if first['action'] == 'DENY' and in_butler and on_whitelist:
            warnings.append(
                'UFW режет доступ, хотя сервис и whitelist настроены — '
                'часто deny стоит ВЫШЕ allow (нажмите «Применить правила» после обновления).'
            )
    else:
        lines.append('Нет явного правила UFW для этого порта — сработает default deny incoming.')

    if port_rules:
        lines.append('Все правила UFW, затрагивающие этот порт и IP (по номеру):')
        for r in port_rules[:25]:
            lines.append(f'  [{r["num"]}] {r["action"]} {r["to"]} from {r["from"]} # {r["comment"]}')
        if len(port_rules) > 25:
            lines.append(f'  … ещё {len(port_rules) - 25}')

    ss = shutil.which('ss') or '/usr/sbin/ss'
    ok_ss, out_ss = _try_command(['ss', '-tlnp'], timeout=10)
    if proto == 'tcp' and ok_ss:
        listening = [ln for ln in out_ss.splitlines() if f':{port} ' in ln or f':{port}\n' in ln]
        if listening:
            lines.append('Слушает на хосте (ss): ' + '; '.join(listening[:3]))
        else:
            warnings.append(
                f'На хосте нет LISTEN на {port}/tcp (не Docker-proxy) — '
                'фаервол тут ни при чём, процесс не слушает порт.'
            )

    docker_ports = _docker_published_host_ports()
    if port in docker_ports:
        lines.append(
            f'Порт {port} опубликован Docker — UFW allow/deny на этот порт почти не влияет '
            '(см. доку Docker). Решает DOCKER-USER + ctorigdstport.'
        )
        if not in_butler:
            warnings.append('Порт в Docker, но не в списке сервисов Butler — должен быть закрыт снаружи.')
        from .ufw_docker import _ufw_docker_block_present
        if not _ufw_docker_block_present():
            warnings.append(
                'Блок ufw-docker не найден в /etc/ufw/after.rules — Apply не выполнил install '
                'или нет sudo на .butler/bin/ufw-docker.'
            )
        else:
            lines.append('ufw-docker: блок BEGIN UFW AND DOCKER в after.rules установлен.')
    elif docker_ports:
        lines.append(f'Другие опубликованные Docker-порты: {sorted(docker_ports)[:12]}…')

    broad = list_broad_allow_rules()
    if broad:
        warnings.append(
            'Есть широкие ALLOW (вся подсеть на любой порт) — см. предупреждение на странице фаервола.'
        )

    return {
        'port': port,
        'src_ip': src_ip,
        'proto': proto,
        'summary': '\n'.join(lines),
        'warnings': warnings,
    }


def build_rules() -> tuple[str, str, list]:
    """Вернуть (человекочитаемый предпросмотр команд, mode, skipped_ips)."""
    commands, mode, skipped = _rule_commands()
    butler_port = _get_butler_port()

    lines = [f'# Butler UFW rules  (режим: {mode})']
    if skipped:
        lines.append('# Пропущены некорректные адреса: ' + ', '.join(skipped))
    lines.append('# Применяются через ufw insert (блок butler выше чужих LAN-allow).')
    lines.append('')
    lines.append('# --- защищённые порты (никогда не блокируются) ---')
    lines.append(f'ufw allow {SSH_PORT}/tcp                    # SSH')
    lines.append(f'ufw allow {butler_port}/tcp                  # Butler web UI')
    lines.append('')
    lines.append('# --- правила сервисов (помечены comment \'butler\') ---')
    if not commands:
        lines.append('# (нет сервисов или списков — правил не будет)')
    for cmd in commands:
        # cmd = ['sudo','-n', _UFW, ...]; печатаем читаемо как "ufw ..."
        lines.append('ufw ' + ' '.join(cmd[3:]))
    return '\n'.join(lines) + '\n', mode, skipped


def _generated_dir() -> Path:
    d = Path('generated')
    d.mkdir(exist_ok=True)
    return d


def write_generated_rules_file() -> Path:
    """Сохранить предпросмотр UFW-команд в файл generated/butler-ufw.sh."""
    generated_file = _generated_dir() / 'butler-ufw.sh'
    rules, _, _ = build_rules()
    generated_file.write_text('#!/usr/bin/env bash\n# Автоген Butler — предпросмотр. Butler применяет правила сам.\n' + rules,
                              encoding='utf-8')
    try:
        generated_file.chmod(0o755)
    except OSError:
        pass
    return generated_file


# ---------------------------------------------------------------------------
# Идемпотентная чистка прежних правил Butler (по комментарию)
# ---------------------------------------------------------------------------

def _list_butler_rule_numbers() -> list[int]:
    """Вернуть номера правил UFW, помеченных комментарием butler, по убыванию.

    Удалять правила нужно от большего номера к меньшему, иначе нумерация
    сдвигается после каждого удаления.
    """
    ok, out = _try_command(_ufw_cmd('status', 'numbered'))
    if not ok:
        return []
    numbers = []
    for line in out.splitlines():
        # Формат строки: "[ 5] 8011/tcp   DENY IN   Anywhere   # butler"
        if f'# {BUTLER_TAG}' not in line:
            continue
        m = re.match(r'\s*\[\s*(\d+)\s*\]', line)
        if m:
            numbers.append(int(m.group(1)))
    return sorted(numbers, reverse=True)


def _delete_tagged_rules(tag):
    # One saved rule deletes both address families. Works even while UFW is inactive.
    result = run_command(_ufw_cmd('show', 'added'), 'Не удалось прочитать правила UFW:')
    rules = []
    for line in result.stdout.splitlines():
        if not line.strip().startswith('ufw '):
            continue
        args = shlex.split(line.strip())[1:]
        if 'comment' in args and args[args.index('comment') + 1] == tag:
            rules.append(args)
    for args in reversed(rules):
        if args[0] == 'route':
            command = _ufw_cmd('--force', 'route', 'delete', *args[1:])
        else:
            command = _ufw_cmd('--force', 'delete', *args)
        run_command(command, 'Не удалось удалить прежнее правило Butler:')
    return len(rules)


def _delete_butler_rules() -> int:
    return _delete_tagged_rules(BUTLER_TAG)


def _ensure_enabled_and_protected() -> None:
    """Подготовить безопасные дефолты: SSH + панель разрешены, политика UFW —
    deny incoming / allow outgoing. Сам UFW включается только после успешной
    установки правил Butler.

    ВАЖНО: не используем reset/disable. Порядок критичен для защиты от self-lockout:
      1. СНАЧАЛА явно allow на SSH (22) и порт панели — до смены default policy.
      2. ЗАТЕМ default deny incoming / allow outgoing (чтобы whitelist без сервисов
         реально закрывал остальное, а не оставлял всё открытым).
      3. Только после установки правил включить UFW.

    `ufw allow` и `ufw default` идемпотентны — повторный вызов ничего не ломает.
    """
    butler_port = _get_butler_port()

    # Шаг 1. Разрешаем SSH и порт Butler ДО смены политики и включения —
    # защита от self-lockout. Правила без тега butler, чтобы чистка их не снесла.
    run_command(_ufw_cmd('allow', f'{SSH_PORT}/tcp'),
                'Не удалось разрешить SSH (22/tcp):')
    run_command(_ufw_cmd('allow', f'{butler_port}/tcp'),
                f'Не удалось защитить порт Butler ({butler_port}/tcp):')

    # Шаг 2. Безопасные дефолтные политики. Даже при пустом списке сервисов
    # входящий трафик будет закрыт (кроме явно разрешённых 22 и порта панели).
    cat = shutil.which('cat') or '/usr/bin/cat'
    ok, defaults = _try_command(['sudo', '-n', cat, '/etc/default/ufw'])
    if not ok or not re.search(r'^DEFAULT_INPUT_POLICY="DROP"$', defaults, re.M):
        run_command(_ufw_cmd('default', 'deny', 'incoming'),
                    'Не удалось задать default deny incoming:')
    if not ok or not re.search(r'^DEFAULT_OUTPUT_POLICY="ACCEPT"$', defaults, re.M):
        run_command(_ufw_cmd('default', 'allow', 'outgoing'),
                    'Не удалось задать default allow outgoing:')

def _enable_ufw_if_needed() -> None:
    """Включить UFW после успешной подготовки правил; Astra локализует status."""
    ok, out = _try_command(_ufw_cmd('status'))
    active = 'Status: active' in out or 'Состояние: активен' in out
    if ok and not active:
        run_command(_ufw_cmd('--force', 'enable'),
                    'Не удалось включить UFW:')


# ---------------------------------------------------------------------------
# Публичный API — apply / reset
# ---------------------------------------------------------------------------

@_exclusive_apply
def apply_firewall_rules() -> tuple[Path, None, None]:
    """Идемпотентно применить правила Butler через UFW.

    Порядок:
      1. Гарантировать, что SSH и порт Butler разрешены.
      2. Удалить прежние правила Butler (по comment 'butler').
      3. Добавить актуальный набор правил из БД.

    Не вызывает reset/disable → sudoers и активные соединения не страдают.
    Возвращает (generated_file, None, None) для совместимости сигнатуры с routes.
    """
    generated_file = write_generated_rules_file()

    # Шаг 1 — защита критичных портов. UFW ещё выключен, если до этого был inactive.
    _ensure_enabled_and_protected()

    # Шаг 2 — снять прежние правила Butler.
    _delete_butler_rules()

    # Шаг 3 — allow/deny в начало; catch-all — сразу после блока butler (выше LAN-allow).
    commands, _mode, _skipped = _rule_commands()
    _apply_butler_ufw_commands(commands)

    # Шаг 4 — включить только после успешного построения набора правил.
    _enable_ufw_if_needed()

    # Host established-flow policy + Docker forwarding policy.
    _apply_docker_isolation()

    # Existing inbound packets now traverse policy rules too (before.rules and
    # DOCKER-USER). Do not delete conntrack: TCP loose pickup can recreate a
    # flow in reverse direction from a server retransmission, bypassing policy.

    return generated_file, None, None


def _revoked_flows(output, local_addresses, specs, whitelist, protected):
    """Original conntrack tuples include the published port before Docker DNAT."""
    for line in output.splitlines():
        protocol = re.search(r'\b(tcp|udp)\s+\d+\s', line)
        original = re.search(r'src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)', line)
        if not protocol or not original:
            continue
        src, dst, sport, dport = original.groups()
        try:
            source = ipaddress.ip_address(src)
            destination = ipaddress.ip_address(dst)
        except ValueError:
            continue
        port = int(dport)
        if str(destination) not in local_addresses or port in protected:
            continue
        if source.is_loopback or str(source) in local_addresses:
            continue
        proto = protocol.group(1)
        allowed = (port, proto) in specs and (
            not whitelist or any(source in network for network in whitelist))
        if not allowed:
            yield proto, str(source), str(destination), sport, dport


def _drop_service_connections() -> None:
    """Revoke inbound flows denied by the new policy, including deleted services."""
    conntrack = shutil.which('conntrack') or '/usr/sbin/conntrack'
    ip = shutil.which('ip') or '/usr/sbin/ip'
    ok, addresses = _try_command([ip, '-j', 'address', 'show'])
    if not ok:
        raise RuntimeError('Не удалось определить адреса сервера для закрытия соединений.')
    local_addresses = {
        str(ipaddress.ip_address(addr['local']))
        for interface in json.loads(addresses)
        for addr in interface.get('addr_info', []) if 'local' in addr
    }
    rows = get_db().execute(
        'SELECT ip_address FROM whitelist_entries WHERE enabled = 1').fetchall()
    ips, invalid = _collect_ips(rows)
    if invalid:
        raise ValueError('Некорректные адреса белого списка.')
    whitelist = [ipaddress.ip_network(value) for value in ips]
    specs = set(_iter_service_specs())
    for family in ('ipv4', 'ipv6'):
        result = run_command(
            ['sudo', '-n', conntrack, '-L', '-f', family, '-o', 'extended'],
            'Не удалось проверить существующие соединения:', timeout=30)
        for proto, src, dst, sport, dport in _revoked_flows(
                result.stdout, local_addresses, specs, whitelist, _protected_ports()):
            command = ['sudo', '-n', conntrack, '-D', '-f', family, '-p', proto,
                       '--orig-src', src, '--orig-dst', dst,
                       '--sport', sport, '--dport', dport]
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            # conntrack returns 1 when the connection has already disappeared.
            if result.returncode not in (0, 1):
                raise RuntimeError('Не удалось закрыть запрещённое соединение: ' + result.stderr)


@_exclusive_apply
def reset_firewall_rules() -> tuple[None, None]:
    """Убрать ТОЛЬКО правила Butler, не трогая остальную конфигурацию UFW.

    Не вызывает `ufw reset` (который стирает sudoers и рвёт соединения).
    SSH и порт Butler остаются разрешёнными. Возвращает (None, None).
    """
    # Гарантируем, что критичные порты открыты (на случай если их не было).
    _ensure_enabled_and_protected()
    _enable_ufw_if_needed()
    # Удаляем только помеченные Butler правила.
    _delete_butler_rules()
    _reset_docker_isolation()
    return None, None


# ---------------------------------------------------------------------------
# Docker — bundled ufw-docker (https://github.com/chaifeng/ufw-docker)
# ---------------------------------------------------------------------------


def _apply_docker_isolation() -> None:
    """ufw-docker install + ufw route allow только для whitelist (см. app/ufw_docker.py)."""
    docker = shutil.which('docker') or '/usr/bin/docker'
    ok, _ = _try_command([docker, 'info'], timeout=10)
    if not ok:
        if Path(docker).exists():
            raise RuntimeError('Docker недоступен: правила контейнеров не применены.')
        return
    from .ufw_docker import sync_docker_whitelist_from_db
    sync_docker_whitelist_from_db()


def _reset_docker_isolation() -> None:
    """Убрать ufw route правила Butler для Docker (блок after.rules не трогаем)."""
    from .ufw_docker import delete_butler_docker_routes
    delete_butler_docker_routes()
