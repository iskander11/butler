#!/usr/bin/env bash
# =============================================================================
# install.sh — установка Butler как системной службы
#
# Совместимо: Astra Linux 1.8 (Orel), Ubuntu 22.04+, Debian 12+
#
# Запуск из папки ~/serv/butler/:
#   ./install.sh
#   ./install.sh --user myuser    # если запускать службу от другого пользователя
#   ./install.sh --port 8080      # если нужен другой порт
#   ./install.sh --uninstall      # удалить службу
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Параметры по умолчанию
# ---------------------------------------------------------------------------
BUTLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNER_DIR="${BUTLER_DIR}/.butler"
VENV_DIR="${BUTLER_DIR}/.butler/.venv"
WHEELS_DIR="${BUTLER_DIR}/.butler/wheels"
WSGI_PATH="${INNER_DIR}/wsgi.py"
ENV_FILE="${BUTLER_DIR}/butler.env"
ENV_EXAMPLE="${BUTLER_DIR}/.butler/env.example"
SERVICE_NAME="butler"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

BUTLER_USER="$(whoami)"
BUTLER_PORT=""
UNINSTALL=0

# ---------------------------------------------------------------------------
# Аргументы
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)      BUTLER_USER="$2"; shift 2 ;;
    --port)      BUTLER_PORT="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)
      echo "Использование: $0 [--user USER] [--port PORT] [--uninstall]"
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Цвета
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "    $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Удаление
# ---------------------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
  echo "Удаление службы Butler..."
  sudo systemctl stop "$SERVICE_NAME"    2>/dev/null || true
  sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  sudo rm -f "$SERVICE_FILE"
  sudo systemctl daemon-reload
  ok "Служба удалена. Файлы приложения и БД не тронуты."
  exit 0
fi

# ---------------------------------------------------------------------------
# Проверки
# ---------------------------------------------------------------------------
[[ -d "$INNER_DIR" ]]   || die "Папка .butler/ не найдена. Распакуй архив правильно."
[[ -f "$WSGI_PATH" ]]   || die "Файл .butler/wsgi.py не найден."
[[ -d "$WHEELS_DIR" ]]  || die "Папка .butler/wheels/ не найдена."

# ---------------------------------------------------------------------------
# Проверка UFW
#
# Butler управляет фаерволом только через UFW. Сами ничего не ставим
# и не включаем (безопаснее на живом удалённом сервере) — только
# проверяем наличие и подсказываем команду установки под текущую ОС.
# ---------------------------------------------------------------------------
if ! PATH="$PATH:/usr/sbin:/sbin" command -v ufw > /dev/null 2>&1; then
  # Определяем менеджер пакетов по ID из /etc/os-release.
  _os_id=""
  [[ -f /etc/os-release ]] && _os_id="$(. /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}")"
  case "$_os_id" in
    *astra*|*debian*|*ubuntu*) UFW_INSTALL_CMD="sudo apt update && sudo apt install -y ufw" ;;
    *fedora*|*rhel*|*centos*)  UFW_INSTALL_CMD="sudo dnf install -y ufw" ;;
    *suse*)                    UFW_INSTALL_CMD="sudo zypper install -y ufw" ;;
    *arch*)                    UFW_INSTALL_CMD="sudo pacman -S --noconfirm ufw" ;;
    *)                         UFW_INSTALL_CMD="sudo apt install -y ufw   # либо менеджер пакетов вашей ОС" ;;
  esac
  warn "UFW не найден — Butler не сможет применять правила фаервола."
  warn "  Установите его вручную:"
  info "  ${UFW_INSTALL_CMD}"
  warn "  Затем разрешите SSH и порт панели ДО включения (защита от self-lockout):"
  info "  sudo ufw allow 22/tcp && sudo ufw allow ${BUTLER_PORT:-5050}/tcp"
  warn "  Включать UFW не обязательно вручную — Butler сам включит его при первом Apply."
  echo ""
else
  UFW_STATUS="$(PATH="$PATH:/usr/sbin:/sbin" sudo -n ufw status 2>/dev/null | head -n1 || true)"
  if [[ "$UFW_STATUS" == *inactive* ]]; then
    ok "UFW установлен, но выключен — Butler включит его при первом Apply (SSH и панель будут разрешены заранее)."
  else
    ok "UFW установлен."
  fi
fi

# ---------------------------------------------------------------------------
# Конфиг
# ---------------------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$ENV_EXAMPLE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    warn "Создан butler.env из шаблона. Отредактируй пароль и пути перед запуском."
  else
    die "butler.env не найден и шаблон недоступен."
  fi
fi

# Читаем порт из конфига если не задан флагом
if [[ -z "$BUTLER_PORT" ]]; then
  BUTLER_PORT="$(grep -m1 '^BUTLER_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
  BUTLER_PORT="${BUTLER_PORT:-5050}"
fi

echo ""
echo "Butler — установка"
echo "  Директория:   $BUTLER_DIR"
echo "  Пользователь: $BUTLER_USER"
echo "  Порт:        $BUTLER_PORT"
echo "  Бэкенд:      UFW"
echo ""

# ---------------------------------------------------------------------------
# Шаг 1 — venv
# ---------------------------------------------------------------------------
echo "Создаю виртуальное окружение..."

PYTHON_BIN=""
# В wheels/ есть пакеты с C-расширением (MarkupSafe) — они жёстко привязаны к ABI.
# Брать "самый новый python" нельзя: нужен тот, под который собран архив.
WHEEL_ABI="$(ls "$WHEELS_DIR" 2>/dev/null | grep -oP 'cp\K\d+' | sort -u | head -1 || true)"

if [[ -n "$WHEEL_ABI" ]]; then
  WANT_PY="python${WHEEL_ABI:0:1}.${WHEEL_ABI:1}"
  if command -v "$WANT_PY" &>/dev/null; then
    PYTHON_BIN="$(command -v "$WANT_PY")"
  else
    die "Wheels собраны под cp${WHEEL_ABI} (${WANT_PY}), но такого Python в системе нет.
    В системе: $(python3 -V 2>&1 || echo 'нет')
    Пересобери дистрибутив под нужную версию, например:
      ./build.sh --python-version 3.11 --abi cp311 --platform manylinux2014_x86_64"
  fi
else
  for PY in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$PY" &>/dev/null; then
      PYTHON_BIN="$(command -v "$PY")"
      break
    fi
  done
fi
[[ -n "$PYTHON_BIN" ]] || die "Python3 не найден.\n  Установи: sudo apt install python3"

"$PYTHON_BIN" -m venv "$VENV_DIR"
ok "venv создан: $VENV_DIR"

# ---------------------------------------------------------------------------
# Шаг 2 — зависимости из wheels
# ---------------------------------------------------------------------------
echo "Устанавливаю зависимости из wheels..."

# Если pip упадёт — не оставляем полусобранный venv.
cleanup_venv() { rm -rf "$VENV_DIR"; }
trap cleanup_venv ERR

"${VENV_DIR}/bin/pip" install \
  --no-index \
  --find-links "$WHEELS_DIR" \
  --quiet \
  -r "${INNER_DIR}/requirements.txt"

trap - ERR

ok "Зависимости установлены."

# ---------------------------------------------------------------------------
# Шаг 2b — ufw-docker (Docker + UFW, вызывается Butler при Apply)
# ---------------------------------------------------------------------------
BUNDLED_UFW_DOCKER="${INNER_DIR}/bundled/ufw-docker"
UFW_DOCKER_BIN="${INNER_DIR}/bin/ufw-docker"
if [[ -f "$BUNDLED_UFW_DOCKER" ]]; then
  mkdir -p "${INNER_DIR}/bin"
  install -m 755 "$BUNDLED_UFW_DOCKER" "$UFW_DOCKER_BIN"
  ok "ufw-docker установлен: $UFW_DOCKER_BIN"
else
  warn "bundled/ufw-docker не найден — Docker-изоляция через Butler не заработает."
fi

# ---------------------------------------------------------------------------
# Шаг 3 — инициализация БД
# ---------------------------------------------------------------------------
echo "Инициализирую базу данных..."
DB_PATH="$(grep -m1 '^BUTLER_DATABASE=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"

if [[ -z "$DB_PATH" ]]; then
  DB_PATH="${BUTLER_DIR}/.butler/instance/butler.sqlite3"
  warn "BUTLER_DATABASE не задан — использую: $DB_PATH"
fi

mkdir -p "$(dirname "$DB_PATH")"

if [[ ! -f "$DB_PATH" ]] || [[ ! -s "$DB_PATH" ]]; then
  (
    cd "$INNER_DIR"
    FLASK_APP=app \
    BUTLER_DATABASE="$DB_PATH" \
      "${VENV_DIR}/bin/flask" --app app init-db
  )
  ok "База данных инициализирована: $DB_PATH"
else
  ok "База данных уже существует: $DB_PATH"
fi

# ---------------------------------------------------------------------------
# Шаг 4 — systemd unit
#
# Важно для Astra Linux 1.8:
#   - PrivateTmp=false : на Astra с включенным МАС PrivateTmp может
#     препятствовать запуску из-за mount-ограничений parsec
#   - NoNewPrivileges=false : gunicorn не должен понижать привилегии
#     до того как созданы дочерние процессы
# ---------------------------------------------------------------------------
echo "Устанавливаю systemd службу..."

sudo tee "$SERVICE_FILE" > /dev/null <<UNIT
[Unit]
Description=Butler — управление доступом через UFW
After=network.target

[Service]
User=${BUTLER_USER}
Group=${BUTLER_USER}
WorkingDirectory=${INNER_DIR}
EnvironmentFile=${ENV_FILE}
Environment=BUTLER_ENV_FILE=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/gunicorn --workers 2 --timeout 300 --bind 0.0.0.0:${BUTLER_PORT} wsgi:app
Restart=always
RestartSec=3

# Astra Linux 1.8 / Parsec MAC совместимость:
# PrivateTmp отключен — из-за ограничений mount-пространств при включенном МАС
PrivateTmp=false

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

sleep 2

if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Служба запущена и работает."
else
  warn "Служба не запустилась. Смотри логи:"
  info "sudo journalctl -u butler -n 30 --no-pager"
  exit 1
fi

# ---------------------------------------------------------------------------
# Шаг 5 — systemd timer для автосбора логов
# ---------------------------------------------------------------------------
TIMER_SERVICE_SRC="${INNER_DIR}/butler-log-import.service"
TIMER_SRC="${INNER_DIR}/butler-log-import.timer"

if [[ -f "$TIMER_SERVICE_SRC" ]] && [[ -f "$TIMER_SRC" ]]; then
  if getent group systemd-journal > /dev/null 2>&1; then
    sudo usermod -aG systemd-journal "${BUTLER_USER}" 2>/dev/null || true
    ok "Пользователь ${BUTLER_USER} добавлен в группу systemd-journal."
  fi

  sudo tee /etc/systemd/system/butler-log-import.service > /dev/null <<TIMER_UNIT
[Unit]
Description=Butler — импорт попыток подключений из journald
After=network.target

[Service]
Type=oneshot
User=${BUTLER_USER}
Group=${BUTLER_USER}
SupplementaryGroups=systemd-journal
WorkingDirectory=${INNER_DIR}
EnvironmentFile=${ENV_FILE}
Environment=BUTLER_ENV_FILE=${ENV_FILE}
ExecStart=${PYTHON_BIN} ${INNER_DIR}/butler-log-import.py
StandardOutput=journal
StandardError=journal
TIMER_UNIT

  sudo cp "$TIMER_SRC" /etc/systemd/system/butler-log-import.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now butler-log-import.timer
  ok "Таймер автосбора логов включён (каждые 5 минут)."
fi

# ---------------------------------------------------------------------------
# Готово
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}Butler успешно установлен.${NC}"
echo ""
echo "  Адрес:    http://$(hostname -I | awk '{print $1}'):${BUTLER_PORT}"
echo "  Бэкенд:   UFW"
echo "  Конфиг:   ${ENV_FILE}"
echo "  База:     ${DB_PATH:-см. butler.env}"
echo ""
echo "  Управление службой:"
echo "    sudo systemctl status butler"
echo "    sudo systemctl restart butler"
echo "    sudo journalctl -u butler -f"
echo ""
echo "  Если sudoers ещё не настроен:"
echo "    ./sudoers.sh"
echo ""
