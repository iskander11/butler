#!/usr/bin/env bash
# =============================================================================
# sudoers.sh — настройка sudoers для Butler (UFW)
#
# Разрешает пользователю вызывать команды UFW, conntrack и journalctl
# без пароля, в том числе без tty (нужно для вызовов из Python/Flask).
#
# Использование:
#   ./sudoers.sh                 # для текущего пользователя
#   ./sudoers.sh --user myuser   # для конкретного пользователя
#   ./sudoers.sh --remove        # удалить правило
# =============================================================================

set -euo pipefail

# Скрипт запускают через sudo, и тогда whoami == root — правило уходило root'у,
# а реальный пользователь оставался без прав.
BUTLER_USER="${SUDO_USER:-$(id -un)}"
SUDOERS_FILE="/etc/sudoers.d/butler"
REMOVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)    BUTLER_USER="$2"; shift 2 ;;
    --remove)  REMOVE=1;        shift ;;
    -h|--help)
      echo "Использование: $0 [--user USER] [--remove]"
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Удаление
# ---------------------------------------------------------------------------
if [[ $REMOVE -eq 1 ]]; then
  sudo rm -f "$SUDOERS_FILE"
  ok "Правило sudoers удалено."
  exit 0
fi

# ---------------------------------------------------------------------------
# Проверяем наличие команд
# ---------------------------------------------------------------------------
REQUIRED_CMDS=(mkdir install test cat journalctl ufw)
OPTIONAL_CMDS=(conntrack iptables ip6tables)

# visudo нужен только для валидации, ищем в PATH
VISUDO_BIN="$(PATH="$PATH:/usr/sbin" command -v visudo 2>/dev/null || true)"
[[ -n "$VISUDO_BIN" ]] || die "Команда visudo не найдена.\n  Убедись что sudo установлен: sudo apt install sudo"

for cmd in "${REQUIRED_CMDS[@]}"; do
  PATH="$PATH:/usr/sbin" command -v "$cmd" > /dev/null ||
    die "Команда не найдена: $cmd\n  Установи: sudo apt install $cmd"
done

for cmd in "${OPTIONAL_CMDS[@]}"; do
  if ! PATH="$PATH:/usr/sbin" command -v "$cmd" > /dev/null 2>&1; then
    warn "Команда '$cmd' не найдена. Conntrack-сброс соединений будет недоступен."
    warn "  Установи: sudo apt install conntrack"
  fi
done

# ---------------------------------------------------------------------------
# Определяем пути к бинарям (полные пути обязательны для sudoers)
# ---------------------------------------------------------------------------
_bin() { PATH="$PATH:/usr/sbin:/usr/bin:/sbin:/bin" command -v "$1"; }

MKDIR_BIN="$(_bin mkdir)"
INSTALL_BIN="$(_bin install)"
TEST_BIN="$(_bin test 2>/dev/null || echo /usr/bin/test)"
[[ "$TEST_BIN" == /* ]] || TEST_BIN="/usr/bin/test"
CAT_BIN="$(_bin cat)"
JOURNALCTL_BIN="$(_bin journalctl)"
UFW_BIN="$(_bin ufw)"

# Butler vendored ufw-docker (.butler/bin/ufw-docker)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UFW_DOCKER_BIN="${SCRIPT_DIR}/.butler/bin/ufw-docker"

# Conntrack / iptables (опционально)
CONNTRACK_BIN=""
if PATH="$PATH:/usr/sbin" command -v conntrack > /dev/null 2>&1; then
  CONNTRACK_BIN="$(_bin conntrack)"
fi
IPTABLES_BIN=""
if PATH="$PATH:/usr/sbin" command -v iptables > /dev/null 2>&1; then
  IPTABLES_BIN="$(_bin iptables)"
fi
IP6TABLES_BIN=""
if PATH="$PATH:/usr/sbin" command -v ip6tables > /dev/null 2>&1; then
  IP6TABLES_BIN="$(_bin ip6tables)"
fi

# ---------------------------------------------------------------------------
# Формируем список всех команд для sudoers
# ---------------------------------------------------------------------------
ALL_BINS=("$UFW_BIN" "$MKDIR_BIN" "$INSTALL_BIN" "$TEST_BIN" "$CAT_BIN" "$JOURNALCTL_BIN")
[[ -x "$UFW_DOCKER_BIN" ]] && ALL_BINS+=("$UFW_DOCKER_BIN")
[[ -n "$CONNTRACK_BIN" ]] && ALL_BINS+=("$CONNTRACK_BIN")
[[ -n "$IPTABLES_BIN" ]] && ALL_BINS+=("$IPTABLES_BIN")
[[ -n "$IP6TABLES_BIN" ]] && ALL_BINS+=("$IP6TABLES_BIN")

# Строка NOPASSWD для sudoers.
# ВАЖНО: sudo матчит команду ВМЕСТЕ С АРГУМЕНТАМИ. Правило вида
#   NOPASSWD: /usr/sbin/ufw
# (и точно так же /usr/sbin/ufw "") разрешает запуск ufw ТОЛЬКО без
# аргументов, поэтому `sudo -n ufw allow 22/tcp` требовал пароль.
# Чтобы разрешить ЛЮБЫЕ аргументы, нужен wildcard '*' после бинаря.
NOPASSWD_LIST=$(printf '%s *, ' "${ALL_BINS[@]}")
NOPASSWD_LIST="${NOPASSWD_LIST%, }"  # убрать трейлинг запятую

# Строки !requiretty для каждой команды
REQUIRETTY_LINES=""
for bin in "${ALL_BINS[@]}"; do
  REQUIRETTY_LINES+="Defaults!${bin} !requiretty"$'\n'
done

# ---------------------------------------------------------------------------
# Пишем файл sudoers
# ---------------------------------------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<RULES
# Managed by sudoers.sh (Butler) — backend: UFW
# !requiretty needed for passwordless sudo from Python/Flask (no tty)
${REQUIRETTY_LINES}
${BUTLER_USER} ALL=(root) NOPASSWD: ${NOPASSWD_LIST}
RULES

"$VISUDO_BIN" -cf "$TMP" > /dev/null || die "Ошибка синтаксиса sudoers — файл не установлен."

sudo install -m 0440 -o root -g root "$TMP" "$SUDOERS_FILE"
sudo "$VISUDO_BIN" -cf "$SUDOERS_FILE" > /dev/null

# ---------------------------------------------------------------------------
# Гарантируем, что @includedir /etc/sudoers.d идёт ПОСЛЕДНИМ в /etc/sudoers.
#
# На Astra Linux (и некоторых других) после @includedir идёт строка
# вида '%astra-admin ALL=(ALL:ALL) ALL'. sudo выбирает ПОСЛЕДНЕЕ
# совпадение, поэтому это общее парольное правило перекрывает наш
# NOPASSWD из sudoers.d => `sudo -n ufw ...` всё равно требует пароль.
# Фикс: перемещаем строку @includedir в самый конец /etc/sudoers,
# чтобы файлы sudoers.d парсились после групповых правил.
MAIN_SUDOERS="/etc/sudoers"
INCLUDE_RE='^[[:space:]]*@includedir[[:space:]]+/etc/sudoers\.d[[:space:]]*$'
INCLUDE_LINE="$(sudo grep -nE "$INCLUDE_RE" "$MAIN_SUDOERS" | head -n1 | cut -d: -f1)"
if [[ -n "$INCLUDE_LINE" ]]; then
  TOTAL_LINES="$(sudo wc -l < "$MAIN_SUDOERS")"
  # Есть ли после @includedir активные правила (не комментарий/пустая)?
  TAIL_RULES="$(sudo sed -n "$((INCLUDE_LINE + 1)),\$p" "$MAIN_SUDOERS" | grep -vE '^[[:space:]]*(#|$)' || true)"
  if [[ -n "$TAIL_RULES" ]]; then
    warn "В /etc/sudoers после @includedir есть правила, перекрывающие NOPASSWD."
    warn "Перемещаю @includedir в конец файла (бэкап: ${MAIN_SUDOERS}.butler.bak)."
    SUDO_TMP="$(mktemp)"
    # Убираем строку @includedir и дописываем её в конец
    sudo grep -vE "$INCLUDE_RE" "$MAIN_SUDOERS" > "$SUDO_TMP"
    printf '@includedir /etc/sudoers.d\n' >> "$SUDO_TMP"
    if sudo "$VISUDO_BIN" -cf "$SUDO_TMP" > /dev/null; then
      sudo cp -a "$MAIN_SUDOERS" "${MAIN_SUDOERS}.butler.bak"
      sudo install -m 0440 -o root -g root "$SUDO_TMP" "$MAIN_SUDOERS"
      ok "@includedir перемещён в конец /etc/sudoers — NOPASSWD теперь приоритетнее."
    else
      warn "visudo отклонил изменённый /etc/sudoers — ОСТАВЛЯЮ КАК БЫЛО."
      warn "Сделайте вручную: перенесите '@includedir /etc/sudoers.d' в конец через 'sudo visudo'."
    fi
    rm -f "$SUDO_TMP"
  fi
fi

ok "Sudoers настроен для пользователя: ${BUTLER_USER}"
echo "  Файл: $SUDOERS_FILE"
echo "  Разрешены: ufw, journalctl${CONNTRACK_BIN:+, conntrack}${IPTABLES_BIN:+, iptables}${IP6TABLES_BIN:+, ip6tables}"
echo ""
warn "Butler применяет правила UFW идемпотентно, без \"ufw reset\" —"
warn "sudoers и активные соединения (SSH) не затрагиваются."
