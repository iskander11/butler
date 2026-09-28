# Butler

Веб-панель управления доступом к обычным сервисам и опубликованным портам Docker.
Сервис вне списка закрыт. Добавленный сервис при пустом активном белом списке
доступен всем; при непустом — только указанным IP и подсетям. Изменения вступают
в силу по кнопке «Применить правила».
SSH (порт 22) и порт веб-панели всегда остаются открытыми.

Подробное описание работы и простое объяснение исправленных ошибок —
**[USER_GUIDE.md](USER_GUIDE.md)**.

Проверяете сборку впервые? Идите сразу в **[TESTING.md](TESTING.md)** — там
пошаговый чек-лист с ожидаемым результатом на каждом шаге.

---

## Как это устроено

Butler ставится на сервер **без интернета и без git**: на машине разработчика
`build.sh` собирает tar-архив, внутри которого лежат исходники и заранее
скачанные Python-wheels. На сервере `install.sh` создаёт venv из этих wheels
и регистрирует systemd-службу.

Отсюда главное ограничение: **wheels привязаны к версии Python на сервере.**
Пакет `MarkupSafe` содержит C-расширение, его wheel помечен ABI-тегом
(`cp311`, `cp312`, …), и на другой версии Python он не установится.

---

## 1. Требования к серверу

| Компонент | Зачем | Установка (Astra/Debian/Ubuntu) |
|---|---|---|
| `python3` + `venv` | запуск приложения | `sudo apt install python3 python3-venv` |
| `ufw` | применение правил фаервола | `sudo apt install ufw` |
| `sudo` | `visudo` для проверки правил | обычно уже стоит |
| `conntrack` | диагностика сетевых соединений | `sudo apt install conntrack` |
| `systemd` | служба и таймер сбора логов | штатно |

Применение не удаляет записи conntrack. Уже установленные входящие соединения
проверяются правилами UFW и DOCKER-USER; conntrack полезен для диагностики.

Одной командой:

```bash
sudo apt update
sudo apt install -y python3 python3-venv ufw conntrack
```

Проверьте версию Python — она понадобится на этапе сборки:

```bash
python3 -V
```

- Astra Linux 1.8 → `3.11.x` → ABI `cp311`
- Ubuntu 24.04 → `3.12.x` → ABI `cp312`
- Debian 12 → `3.11.x` → ABI `cp311`

---

## 2. Сборка дистрибутива (машина разработчика)

ABI указывается **под Python сервера, а не сборочной машины**. Если версии
совпадают, флаги можно опустить, но лучше задавать явно.

```bash
git clone https://github.com/SVATOY22rus/butler.git
cd butler
./build.sh --python-version 3.11 --abi cp311
```

Результат: `../butler-YYYYMMDD-HHMMSS.tar.gz`

Флаги:

| Флаг | Значение по умолчанию | Когда менять |
|---|---|---|
| `--python-version` | версия локального Python | всегда, если сервер на другой версии |
| `--abi` | ABI локального Python | вместе с `--python-version` |
| `--platform` | `manylinux2014_x86_64` | другая архитектура (например, `manylinux2014_aarch64`) |
| `--output` | `../butler-<дата>.tar.gz` | нужен конкретный путь |
| `--no-wheels` | — | wheels уже скачаны, пересобрать только архив |

Сборка падает с явной ошибкой, если под заказанный ABI нет бинарных wheels
или если в `wheels/` попал пакет чужого ABI. Это сделано специально:
раньше такая сборка проходила «успешно», а падала уже на сервере.

Проверить, что в архиве нужный ABI:

```bash
tar -tzf ../butler-*.tar.gz | grep markupsafe
# ожидается: ...wheels/MarkupSafe-2.1.3-cp311-cp311-manylinux_2_17_x86_64...whl
```

---

## 3. Установка на сервер

```bash
# 1. Перекинуть архив (каталог должен существовать)
scp butler-*.tar.gz user@server:~/

# 2. На сервере — распаковать
ssh user@server
tar -xzf butler-*.tar.gz     # создаст каталог butler/
cd butler

# 3. Настроить конфиг ДО установки (см. раздел 4)
cp butler.env.example butler.env
nano butler.env

# 4. Установить службу
./install.sh

# 5. Выдать права на управление UFW
./sudoers.sh
```

`install.sh` запускать **от имени того пользователя, под которым будет
работать служба**, не от root. Внутри он сам вызывает `sudo` там, где нужно,
и спросит пароль.

Полезные флаги:

```bash
./install.sh --port 8080        # другой порт
./install.sh --user butleruser  # служба от другого пользователя
./install.sh --uninstall        # снять службу (файлы и БД не тронет)
```

Если пропустить шаг 3, `install.sh` сам создаст `butler.env` из шаблона —
но тогда панель поднимется с логином `admin` и паролем `change-me-now`.

### Что именно меняется в системе

`install.sh`:

- создаёт `/etc/systemd/system/butler.service` и включает его;
- создаёт `butler-log-import.service` + `.timer` (сбор попыток подключений из
  journald каждые 5 минут);
- добавляет пользователя в группу `systemd-journal` — **чтобы членство
  вступило в силу, нужно перезайти в сессию** (`exit` и снова `ssh`);
- создаёт БД в `.butler/instance/butler.sqlite3`.

`sudoers.sh`:

- создаёт `/etc/sudoers.d/butler` с правилом `NOPASSWD` для `ufw`,
  `conntrack`, `journalctl` и вспомогательных команд;
- **при необходимости переносит строку `@includedir /etc/sudoers.d` в конец
  `/etc/sudoers`** с бэкапом в `/etc/sudoers.butler.bak`.

Последнее нужно из-за особенности Astra Linux: в sudoers побеждает
*последнее* совпавшее правило, а не самое специфичное. Строка
`%astra-admin ALL=(ALL:ALL) ALL` стоит ниже `@includedir` и перекрывала
`NOPASSWD`, из-за чего Butler получал `sudo: a password is required`.
Изменение применяется только после проверки через `visudo -c`.

Флаги:

```bash
./sudoers.sh --user loktar   # выписать правило конкретному пользователю
./sudoers.sh --remove        # удалить правило
```

---

## 4. Конфигурация (`butler.env`)

| Переменная | Обязательна | Описание |
|---|---|---|
| `BUTLER_SECRET_KEY` | **да** | ключ подписи сессий; со значением по умолчанию сессии предсказуемы |
| `BUTLER_ADMIN_USER` | да | логин в панель |
| `BUTLER_ADMIN_PASS` | **да** | пароль в панель |
| `BUTLER_PORT` | нет | порт панели, по умолчанию `5050` |
| `BUTLER_HOST` | нет | адрес привязки, по умолчанию `0.0.0.0` |
| `BUTLER_DATABASE` | нет | путь к SQLite; пусто — подставит `install.sh` |

Сгенерировать ключ:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

После правки конфига перезапустите службу:

```bash
sudo systemctl restart butler
```

---

## 5. Проверка без установки службы

```bash
./butler              # gunicorn в терминале, Ctrl+C — стоп
./butler --port 8080
```

Требует уже созданного venv, то есть однократно выполненного `install.sh`.
Слушает `0.0.0.0`, так что панель доступна и по внешнему адресу.

---

## 6. Обновление

```bash
cd ~
tar -xzf butler-НОВЫЙ.tar.gz          # поверх существующего каталога
cd butler
rm -rf .butler/.venv                  # обязательно, если менялась версия Python
./install.sh
```

Перед обновлением сохраните `butler.env` и базу по пути `BUTLER_DATABASE`.
В стандартной установке база находится в `.butler/instance/butler.sqlite3`;
не удаляйте этот каталог при обновлении.

Удалить `.butler/.venv` нужно потому, что старое окружение может быть собрано
под другой ABI; `install.sh` пересоздаёт venv, но остатки прошлой установки
приводят к неочевидным ошибкам импорта.

---

## 7. Управление службой

```bash
sudo systemctl status butler
sudo systemctl restart butler
sudo journalctl -u butler -f

# таймер сбора попыток подключений
systemctl status butler-log-import.timer
sudo journalctl -u butler-log-import -n 50
```

---

## Структура на сервере

```
~/butler/
├── butler.env              ← конфиг (правится руками)
├── butler.env.example      ← шаблон конфига
├── butler                  ← тестовый запуск в терминале
├── install.sh              ← установка службы
├── sudoers.sh              ← выдача прав на ufw
└── .butler/                ← подкапотное, руками не трогать
    ├── app/                    приложение (Flask)
    ├── wheels/                 wheels под конкретный ABI
    ├── .venv/                  окружение (создаёт install.sh)
    ├── instance/               база данных SQLite
    ├── wsgi.py
    ├── logparse.py
    ├── requirements.txt
    ├── env.example
    ├── butler-log-import.py
    ├── butler-log-import.service
    └── butler-log-import.timer
```

---

## Безопасность

- Панель ходит по HTTP без шифрования. Не выставляйте её в интернет напрямую —
  только внутренняя сеть, VPN или обратный прокси с TLS.
- Правило sudoers даёт беспарольный `sudo` на `ufw`, `conntrack`, `journalctl`,
  а также на `mkdir`, `install`, `test` и `cat`. Последние четыре — фактически
  полный root (через `sudo install` можно записать любой файл, через
  `sudo cat` прочитать `/etc/shadow`). Заводите Butler под отдельным
  сервисным пользователем, а не под своей учётной записью.
- Смените `BUTLER_SECRET_KEY` и `BUTLER_ADMIN_PASS` до первого запуска.

---

## Стек

- **Flask 2.2** — веб-интерфейс (совместимость с Python 3.7+)
- **SQLite** — хранение данных
- **UFW** — фильтрация трафика
- **Gunicorn** — production WSGI-сервер
- **systemd** — служба и таймер

## Тесты

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
```

Обновление проверено на Linux с Python 3.11: 86 тестов пройдено.
Пользовательские сетевые проверки описаны в [TESTING.md](TESTING.md).
