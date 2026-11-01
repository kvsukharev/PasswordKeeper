# PasswordKeeper

Клиент-серверный менеджер паролей с шифрованием **на стороне клиента**. Сервер хранит только зашифрованный текст — даже при взломе сервера ваши данные останутся недоступны.

---

## Содержание

- [Как это работает](#как-это-работает)
- [Быстрый старт](#быстрый-старт)
- [Команды клиента](#команды-клиента)
  - [Аутентификация](#аутентификация)
  - [Управление секретами](#управление-секретами)
  - [Бинарные файлы](#бинарные-файлы)
  - [Одноразовые пароли (OTP)](#одноразовые-пароли-otp)
  - [Синхронизация](#синхронизация)
  - [Терминальный интерфейс (TUI)](#терминальный-интерфейс-tui)
  - [Конфигурация и флаги](#конфигурация-и-флаги)
- [Запуск сервера](#запуск-сервера)
- [Сборка из исходников](#сборка-из-исходников)
- [Соответствие техническому заданию](#соответствие-техническому-заданию)

---

## Как это работает

При входе PasswordKeeper выводит из вашего мастер-пароля **ключ шифрования** (AES-256-GCM). Этот ключ существует только в памяти приложения и **никогда не покидает ваше устройство**. Все данные шифруются до отправки на сервер. Сервер видит только зашифрованный набор байт.

```
Ваш мастер-пароль
       │
       ├─► auth_key ──► сервер (хешируется Argon2id, используется для входа)
       │
       └─► enc_key ───► только клиент (шифрует/расшифровывает данные)
```

Потеря мастер-пароля означает потерю доступа к данным — восстановление не предусмотрено.

---

## Быстрый старт

### Для нового пользователя

```bash
# 1. Зарегистрироваться
passwordkeeper register

# 2. Войти
passwordkeeper login

# 3. Добавить первый секрет
passwordkeeper add credentials --name "GitHub"

# 4. Посмотреть список секретов
passwordkeeper list

# 5. Синхронизировать с другим устройством
passwordkeeper sync
```

### Для существующего пользователя

```bash
# Войти (локальный кэш синхронизируется автоматически)
passwordkeeper login

# Получить сохранённый пароль
passwordkeeper get "GitHub" --show
```

---

## Команды клиента

### Аутентификация

```bash
# Зарегистрировать нового пользователя
# Запросит логин и мастер-пароль (дважды, ввод скрыт)
passwordkeeper register

# Войти в систему
# Запросит логин и мастер-пароль
passwordkeeper login

# Выйти (токены удаляются с устройства)
passwordkeeper logout

# Показать версию, дату сборки и коммит
passwordkeeper version
```

### Управление секретами

#### Добавление секретов

Команда `add` запрашивает нужные поля интерактивно:

```bash
# Учётные данные (логин + пароль + URL)
passwordkeeper add credentials --name "GitHub"
passwordkeeper add credentials --name "Work VPN"

# Произвольный текст (заметка, SSH-ключ, токен и т. п.)
passwordkeeper add text --name "SSH passphrase"

# Данные банковской карты
# Валидация: алгоритм Луна, срок действия, CVV 3–4 цифры
passwordkeeper add card --name "Visa Tinkoff"

# OTP (одноразовые пароли, TOTP)
passwordkeeper add otp --name "GitHub 2FA"
```

**Добавить метаданные и заметку:**

```bash
passwordkeeper add credentials \
  --name "GitLab" \
  --meta "site:gitlab.com" \
  --meta "team:backend" \
  --note "корпоративный аккаунт"
```

#### Список секретов

```bash
# Все секреты из локального кэша
passwordkeeper list
```

Пример вывода:

```
GitHub          credentials   v3   2024-11-01
Visa Tinkoff    card          v1   2024-10-15
SSH passphrase  text          v2   2024-09-30
GitHub 2FA      otp           v1   2024-11-01
```

Секрет помечен `[!]` если обнаружен конфликт при синхронизации.

#### Просмотр секрета

```bash
# Показать секрет; пароль и CVV скрыты звёздочками
passwordkeeper get "GitHub"

# Показать все поля, включая пароль
passwordkeeper get "GitHub" --show
```

Пример вывода без `--show`:

```
Name:     GitHub
Type:     credentials
Version:  3

Login:    alice@example.com
Password: ***
URL:      https://github.com
```

#### Редактирование

```bash
# Интерактивное редактирование (пустой ввод = оставить текущее значение)
passwordkeeper edit "GitHub"
```

#### Удаление

```bash
# Запросит подтверждение
passwordkeeper delete "GitHub"

# Без подтверждения
passwordkeeper delete "GitHub" --yes
```

### Бинарные файлы

Файлы шифруются **до** отправки на сервер. Лимит по умолчанию — 50 МБ.

```bash
# Зашифровать и загрузить файл на сервер
passwordkeeper upload --name "passport.pdf" --file ~/documents/passport.pdf

# Скачать и расшифровать файл
passwordkeeper download "passport.pdf" ~/downloads/passport.pdf
```

### Одноразовые пароли (OTP)

```bash
# Добавить TOTP-секрет (запросит base32-ключ, алгоритм, количество цифр и период)
passwordkeeper add otp --name "GitHub 2FA"

# Получить текущий код с обратным отсчётом
passwordkeeper otp "GitHub 2FA"
# → 483921  (27s remaining)
```

Поддерживаемые алгоритмы: SHA1, SHA256, SHA512. Количество цифр: 6 или 8. Период: обычно 30 с.

### Синхронизация

Синхронизация происходит **автоматически** при входе. Принудительная синхронизация:

```bash
passwordkeeper sync
```

**Работа без сети:** `list` и `get` работают по локальному кэшу. Изменения (добавление, редактирование, удаление) ставятся в очередь и отправляются при следующей синхронизации.

```
Offline: secret "GitHub" queued for next sync.
```

**Конфликты:** если одна и та же запись была изменена на двух устройствах, по умолчанию побеждает версия сервера, а локальная копия сохраняется под именем `"GitHub (конфликт)"`.

### Терминальный интерфейс (TUI)

```bash
passwordkeeper tui
```

Управление:

| Клавиша | Действие |
|---------|----------|
| `↑` / `↓` | Навигация по списку |
| `Enter` | Открыть секрет |
| `/` | Фильтр по названию |
| `Esc` / `Backspace` | Назад |
| `q` | Выход |

### Конфигурация и флаги

Адрес сервера и сертификат CA можно задать флагами, переменными окружения или обоими способами:

| Флаг | Переменная окружения | По умолчанию | Описание |
|------|---------------------|--------------|----------|
| `--server` | `PASSWORDKEEPER_SERVER` | `localhost:9090` | Адрес сервера |
| `--ca` | `PASSWORDKEEPER_CA_CERT` | — | Путь к CA-сертификату |
| `--data-dir` | `PASSWORDKEEPER_DATA_DIR` | `~/.config/passwordkeeper` | Каталог кэша |

Примеры:

```bash
# Через флаги
passwordkeeper --server 10.0.0.1:9090 --ca /etc/ssl/ca.crt list

# Через переменные окружения
export PASSWORDKEEPER_SERVER=10.0.0.1:9090
export PASSWORDKEEPER_CA_CERT=/etc/ssl/ca.crt
passwordkeeper list
```

---

## Запуск сервера

### Через Docker Compose (рекомендуется)

```bash
# Сгенерировать самоподписанный TLS-сертификат для разработки
make certs

# Запустить PostgreSQL и сервер
docker compose up
```

### Вручную

```bash
passwordkeeper-server serve \
  --dsn    "postgres://user:pass@localhost:5432/passwordkeeper?sslmode=disable" \
  --tls-cert deploy/certs/server.crt \
  --tls-key  deploy/certs/server.key \
  --jwt-secret "$(openssl rand -hex 32)"
```

Параметры сервера:

| Флаг | Переменная окружения | По умолчанию | Описание |
|------|---------------------|--------------|----------|
| `--addr` | `PASSWORDKEEPER_GRPC_ADDR` | `:9090` | Адрес gRPC-сервера |
| `--dsn` | `PASSWORDKEEPER_DATABASE_DSN` | — | PostgreSQL DSN |
| `--tls-cert` | `PASSWORDKEEPER_TLS_CERT` | — | Путь к TLS-сертификату |
| `--tls-key` | `PASSWORDKEEPER_TLS_KEY` | — | Путь к TLS-ключу |
| `--jwt-secret` | `PASSWORDKEEPER_JWT_SECRET` | — | HMAC-секрет для JWT |
| `--max-binary-mb` | `PASSWORDKEEPER_MAX_BINARY_MB` | `50` | Лимит бинарных данных (МиБ) |
| `--login-rate-rps` | `PASSWORDKEEPER_LOGIN_RATE_RPS` | `5` | Rate limit входа (запросов/с на IP) |
| `--login-rate-burst` | `PASSWORDKEEPER_LOGIN_RATE_BURST` | `10` | Burst для rate limiter |

---

## Сборка из исходников

### Требования

- Go 1.23+
- Docker + Docker Compose
- `buf` (генерация protobuf-кода): `make tools`
- `openssl` (TLS-сертификаты): `make certs`

### Команды сборки

```bash
# Установить инструменты разработки (buf, golangci-lint, mockgen)
make tools

# Собрать клиент и сервер
make build

# Собрать только клиент
make build-client

# Кросс-компиляция клиента для всех платформ → dist/
make release
```

Собранные бинарники:

| Файл | Платформа |
|------|-----------|
| `dist/passwordkeeper_linux_amd64` | Linux x86-64 |
| `dist/passwordkeeper_linux_arm64` | Linux ARM64 |
| `dist/passwordkeeper_darwin_amd64` | macOS Intel |
| `dist/passwordkeeper_darwin_arm64` | macOS Apple Silicon |
| `dist/passwordkeeper_windows_amd64.exe` | Windows x86-64 |

Версия задаётся через `-ldflags`:

```bash
go build \
  -ldflags "-X main.buildVersion=1.0.0 \
            -X main.buildDate=$(date -u +%F) \
            -X main.buildCommit=$(git rev-parse --short HEAD)" \
  ./cmd/client
```

### Тесты

```bash
make test             # юнит-тесты
make cover            # тесты + проверка покрытия ≥ 70%
make lint             # golangci-lint
make test-integration # интеграционные тесты (требует Docker)
```

---

## Соответствие техническому заданию

Раздел **«Исходный текст задачи»** из ТЗ определяет обязательные и необязательные требования.

### Обязательные требования

#### Сервер

| Требование | Статус | Реализация |
|------------|--------|------------|
| Регистрация, аутентификация и авторизация пользователей | ✅ | `register` / `login` / JWT access + refresh с ротацией |
| Хранение приватных данных | ✅ | PostgreSQL, payload — только шифротекст |
| Синхронизация между несколькими клиентами одного владельца | ✅ | `SyncService`: Pull(since_version) + Push с обнаружением конфликтов |
| Передача приватных данных владельцу по запросу | ✅ | `SecretService.Get`, `Download` (стриминг) |

#### Клиент

| Требование | Статус | Реализация |
|------------|--------|------------|
| Аутентификация на удалённом сервере | ✅ | `login` / `logout`, автообновление access-токена |
| Доступ к приватным данным по запросу | ✅ | `get`, `list`, `download` |
| CLI для Windows, Linux, macOS | ✅ | Бинарники для 5 платформ в `dist/` |
| Версия и дата сборки | ✅ | `version` — выводит версию, дату, коммит из `-ldflags` |

#### Типы хранимых данных

| Тип | Статус | Команда |
|-----|--------|---------|
| Пары логин/пароль | ✅ | `add credentials` |
| Произвольные текстовые данные | ✅ | `add text` |
| Произвольные бинарные данные | ✅ | `upload` / `download` |
| Данные банковских карт | ✅ | `add card` (проверка номера по Луну, срока, CVV) |
| Произвольная текстовая метаинформация | ✅ | Флаги `--meta key:value` и `--note` у любого типа |

#### Качество

| Требование | Статус | Детали |
|------------|--------|--------|
| Покрытие тестами ≥ 70% | ✅ | 71.3% (без `api/gen`, `cmd/`, `server/storage`) |
| Документация (godoc) | ✅ | `doc.go` в каждом пакете, комментарии у всех экспортируемых символов |
| README с архитектурой, сборкой, примерами | ✅ | Данный документ |

### Необязательные требования

| Функция | Статус | Детали |
|---------|--------|--------|
| Поддержка OTP (TOTP) | ✅ | `add otp`, `otp <name>` — генерация TOTP-кодов (pquerna/otp) |
| Терминальный интерфейс (TUI) | ✅ | `tui` — bubbletea, список + детали с дешифрованием |
| Бинарный протокол | ✅ | gRPC + Protocol Buffers поверх TLS 1.3 |
| Интеграционные тесты | ✅ | testcontainers-go (postgres:16-alpine), build-тег `integration` |
| Swagger / OpenAPI | ❌ | Не реализовано |

### Итог

Все обязательные требования ТЗ выполнены. Из 5 необязательных функций реализованы 4 (OTP, TUI, бинарный протокол, интеграционные тесты). Единственное, что не реализовано — Swagger-описание протокола.
