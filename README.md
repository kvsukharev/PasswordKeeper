# PasswordKeeper

Клиент-серверная система для надёжного и безопасного хранения логинов, паролей, бинарных данных и прочей приватной информации. Данные шифруются **на клиенте** (AES-256-GCM) — сервер хранит только шифротекст.

## Возможности

- Хранение четырёх типов секретов: **пары логин/пароль**, **произвольный текст**, **бинарные файлы**, **данные банковских карт**; опционально — **OTP (TOTP)**
- К любому секрету можно добавить произвольные метаданные (пары ключ–значение) и текстовую заметку
- Синхронизация данных между несколькими авторизованными клиентами одного владельца
- Работа **офлайн**: чтение из локального кэша, изменения ставятся в очередь и отправляются при следующем `sync`
- Кроссплатформенный CLI для **Windows**, **Linux** и **macOS** (amd64 и arm64)
- Терминальный интерфейс (TUI) для навигации по секретам без ввода команд

## Безопасность

- **Zero-knowledge**: ключ шифрования выводится из мастер-пароля на клиенте через Argon2id и **никогда не покидает клиент** и не пишется на диск
- На сервер передаётся только `auth_key` (тоже производный от пароля), там он ещё раз хешируется Argon2id
- Токены: access JWT (15 мин) + refresh (30 дней) с ротацией; в БД хранится только хеш refresh-токена
- Транспорт: gRPC поверх TLS 1.3
- Пароли, ключи, токены и содержимое секретов **никогда не попадают в логи**

## Стек

| Компонент | Технология |
|-----------|-----------|
| Язык | Go 1.23+ |
| Протокол | gRPC + Protocol Buffers / TLS 1.3 |
| БД сервера | PostgreSQL 16 (pgx, goose-миграции) |
| Кэш клиента | SQLite (modernc.org/sqlite, без CGO) |
| CLI | cobra |
| TUI | bubbletea + bubbles + lipgloss |
| OTP | pquerna/otp (TOTP RFC 6238) |

## Требования

- Go 1.23+
- Docker + Docker Compose (для запуска сервера)
- `buf` — генерация protobuf-кода: `make tools`
- `openssl` — генерация TLS-сертификатов для разработки: `make certs`

## Быстрый старт

```bash
# 1. Установить вспомогательные инструменты (buf, golangci-lint, mockgen)
make tools

# 2. Сгенерировать самоподписанные TLS-сертификаты для разработки
make certs

# 3. Запустить PostgreSQL и сервер
docker compose up

# 4. Собрать клиент
make build-client

# 5. Зарегистрироваться и войти
passwordkeeper register
passwordkeeper login
```

## Сборка

```bash
make build          # server + client
make build-client   # только клиент
make build-server   # только сервер
make release        # кросс-компиляция клиента для 5 платформ → dist/
```

Версия, дата сборки и коммит задаются через `-ldflags`:

```bash
go build -ldflags "-X main.buildVersion=1.0.0 -X main.buildDate=$(date -u +%F) -X main.buildCommit=$(git rev-parse --short HEAD)" ./cmd/client
```

## Команды клиента

### Аутентификация

```bash
passwordkeeper register                   # новый пользователь
passwordkeeper login                      # вход (пароль вводится скрыто)
passwordkeeper logout                     # выход, токены удаляются
passwordkeeper version                    # версия, дата и коммит сборки
```

### Управление секретами

```bash
# Добавить секрет (тип: credentials, text, card, binary, otp)
passwordkeeper add credentials --name "GitHub"
passwordkeeper add text        --name "SSH passphrase"
passwordkeeper add card        --name "Visa"
passwordkeeper add otp         --name "GitHub 2FA"

# Добавить с метаданными
passwordkeeper add credentials --name "GitHub" --meta site:github.com --note "work account"

# Список секретов из локального кэша
passwordkeeper list

# Показать секрет (пароль/CVV скрыты без --show)
passwordkeeper get "GitHub"
passwordkeeper get "GitHub" --show

# Редактировать
passwordkeeper edit "GitHub"

# Удалить (запрашивает подтверждение)
passwordkeeper delete "GitHub"
```

### Бинарные файлы

```bash
# Загрузить файл на сервер (шифруется перед отправкой)
passwordkeeper upload --name "passport.pdf" --file ~/documents/passport.pdf

# Скачать файл
passwordkeeper download "passport.pdf" ~/downloads/passport.pdf
```

### OTP (одноразовые пароли)

```bash
# Добавить TOTP-секрет (base32, алгоритм SHA1/SHA256/SHA512, период, цифры)
passwordkeeper add otp --name "GitHub 2FA"

# Сгенерировать текущий код с обратным отсчётом
passwordkeeper otp "GitHub 2FA"
# → 483921  (27s remaining)
```

### Синхронизация

```bash
# Синхронизировать с сервером вручную
passwordkeeper sync

# Конфликты: локальная версия сохраняется с суффиксом "(конфликт)",
# серверная версия побеждает (по умолчанию)
```

### Терминальный интерфейс (TUI)

```bash
passwordkeeper tui
```

Клавиши в TUI: `↑/↓` — навигация, `Enter` — открыть секрет, `/` — фильтр, `Esc` — назад, `q` — выход.

### Флаги и конфигурация

```bash
# Адрес сервера и путь к CA-сертификату
passwordkeeper --server 10.0.0.1:9090 --ca /etc/ssl/ca.crt list

# Переменные окружения (альтернатива флагам)
PASSWORDKEEPER_SERVER=10.0.0.1:9090
PASSWORDKEEPER_CA_CERT=/etc/ssl/ca.crt
PASSWORDKEEPER_DATA_DIR=~/.config/passwordkeeper
```

## Тесты и качество

```bash
make test             # unit-тесты (с race detector при наличии gcc)
make cover            # тесты + проверка покрытия ≥ 70%
make lint             # golangci-lint
make test-integration # интеграционные тесты (требует Docker)
```

Интеграционные тесты поднимают `postgres:16-alpine` через testcontainers-go и проверяют все три репозитория (`UserRepo`, `TokenRepo`, `SecretRepo`) и сквозной сценарий двух клиентов с конфликтом версий.

## Запуск сервера

```bash
# Через docker-compose (рекомендуется)
docker compose up

# Вручную
passwordkeeper-server serve \
  --dsn "postgres://user:pass@localhost:5432/passwordkeeper?sslmode=disable" \
  --tls-cert deploy/certs/server.crt \
  --tls-key  deploy/certs/server.key \
  --jwt-secret "$(openssl rand -hex 32)"
```

Параметры сервера (флаги или env-переменные):

| Флаг | Env | По умолчанию | Описание |
|------|-----|-------------|----------|
| `--addr` | `PASSWORDKEEPER_GRPC_ADDR` | `:9090` | gRPC-адрес |
| `--dsn` | `PASSWORDKEEPER_DATABASE_DSN` | — | PostgreSQL DSN |
| `--tls-cert` | `PASSWORDKEEPER_TLS_CERT` | — | Путь к сертификату |
| `--tls-key` | `PASSWORDKEEPER_TLS_KEY` | — | Путь к ключу |
| `--jwt-secret` | `PASSWORDKEEPER_JWT_SECRET` | — | HMAC-секрет для JWT |
| `--max-binary-mb` | `PASSWORDKEEPER_MAX_BINARY_MB` | `50` | Лимит бинарных секретов (МиБ) |
| `--login-rate-rps` | `PASSWORDKEEPER_LOGIN_RATE_RPS` | `5` | Rate limit login/register (req/s на IP) |
| `--login-rate-burst` | `PASSWORDKEEPER_LOGIN_RATE_BURST` | `10` | Burst для rate limiter |

## Генерация protobuf

```bash
make proto  # генерирует api/gen/ из api/proto/*.proto (требует buf)
```

## Структура репозитория

```
cmd/server/          — точка входа сервера
cmd/client/          — точка входа клиента (CLI)
api/proto/           — .proto-файлы (AuthService, SecretService, SyncService)
api/gen/             — сгенерированный protobuf-код (не редактировать вручную)
internal/server/
  auth/              — JWT-менеджер, Argon2id хеширование
  config/            — конфигурация сервера (флаги + env)
  service/           — бизнес-логика (AuthService, SecretService, SyncService)
  storage/           — pgx-репозитории, goose-миграции
  transport/         — gRPC-обработчики, interceptor авторизации, rate limiter
internal/client/
  commands/          — cobra-команды (register, login, add, list, get, …, tui, otp)
  crypto/            — AES-256-GCM, Argon2id key derivation
  grpc/              — gRPC-клиент с TLS
  storage/           — SQLite-кэш (секреты, сессия, очередь изменений)
  sync/              — алгоритм синхронизации
  tui/               — bubbletea TUI-модель
  validator/         — Luhn, CVV, expiry, OTP base32
internal/model/      — доменные типы (Secret, Payload, OTPPayload, …)
internal/errs/       — общие ошибки (ErrNotFound, ConflictError, …)
migrations/          — SQL-миграции goose
deploy/              — docker-compose, Dockerfile, скрипты TLS-сертификатов
```
