# PasswordKeeper

Клиент-серверный менеджер паролей на Go. Пользователь хранит логины, пароли, текст, файлы и данные банковских карт и синхронизирует их между устройствами.

Данные шифруются **на клиенте** (AES-256-GCM); сервер видит только шифротекст.

## Архитектура

- **Сервер**: gRPC + TLS 1.3, PostgreSQL 16, goose-миграции
- **Клиент**: CLI (cobra), локальный SQLite-кэш (modernc.org/sqlite, без CGO)
- **Zero-knowledge**: ключ шифрования выводится из мастер-пароля на клиенте и никогда не покидает его

## Требования

- Go 1.23+
- Docker + Docker Compose
- buf (генерация protobuf): `make tools`
- openssl (генерация сертификатов для разработки)

## Быстрый старт

```bash
# 1. Установить инструменты
make tools

# 2. Сгенерировать TLS-сертификаты для разработки
make certs

# 3. Запустить PostgreSQL и сервер
docker compose up

# 4. Собрать клиент
make build-client
```

## Сборка

```bash
make build          # server + client
make build-client   # только клиент
make build-server   # только сервер
make release        # кросс-компиляция клиента под все платформы (dist/)
```

## Тесты и качество

```bash
make test   # unit-тесты
make cover  # тесты + проверка покрытия ≥ 70%
make lint   # golangci-lint
```

## Генерация protobuf

```bash
make proto  # генерирует api/gen/ из api/proto/*.proto
```

## Примеры команд клиента

```bash
passwordkeeper version
passwordkeeper register
passwordkeeper login
passwordkeeper add credentials --name "GitHub" --meta site=github.com
passwordkeeper list
passwordkeeper get <id> --show
passwordkeeper sync
passwordkeeper logout
```

## Структура репозитория

```
cmd/server          — точка входа сервера
cmd/client          — точка входа клиента (CLI)
api/proto           — .proto-файлы
api/gen             — сгенерированный protobuf-код (не редактировать вручную)
internal/server/    — transport / service / storage / auth
internal/client/    — commands / crypto / storage / sync
internal/model      — доменные типы
migrations/         — SQL-миграции (goose)
deploy/             — docker-compose, Dockerfile, скрипты сертификатов
```
