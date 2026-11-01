# Threat Intelligence Exchange Service

REST-сервис на Go для хранения и обмена информацией о файловых угрозах по MD5-хешу. Реализованы операции создания, получения и полной замены записи об угрозе.

## Возможности

- `GET /info/{md5}` — получить запись об угрозе по MD5.
- `POST /info` — создать запись; MD5 уникален.
- `PUT /info/{md5}` — полностью заменить редактируемые поля существующей записи.
- `GET /healthz` — проверить работоспособность HTTP-сервера.
- PostgreSQL через `pgx/v5`, пул соединений и SQL-миграции, встроенные в бинарный файл.
- Расширенная модель угрозы и валидация данных.
- Единый JSON-формат ошибок и соответствующие HTTP-коды.
- Unit-тесты доменной логики, HTTP-обработчиков и middleware.
- Интеграционный тест PostgreSQL, который использует только отдельную базу с суффиксом `_test` и уникальный MD5 для каждой записи.
- Dockerfile с многоэтапной сборкой и Docker Compose.
- Опциональные API Key, Rate Limit и HTTPS.
- OpenAPI 3.0 спецификация в `api/openapi.yaml`.

## Модель угрозы

| Поле | Тип | Назначение |
|---|---|---|
| `md5` | string | Уникальный MD5 файла, 32 шестнадцатеричных символа |
| `name` | string | Название обнаружения, обязательно, до 255 символов |
| `category` | string | `unknown`, `malware`, `phishing`, `ransomware`, `exploit`, `suspicious` |
| `severity` | string | `unknown`, `info`, `low`, `medium`, `high`, `critical` |
| `description` | string | Описание угрозы, до 4000 символов |
| `family` | string | Семейство, до 255 символов |
| `confidence` | integer | Уверенность обнаружения от 0 до 100 |
| `source` | string | Источник данных, до 255 символов |
| `tags` | string[] | До 20 тегов, каждый до 64 символов |
| `created_at` | date-time | Время создания записи в UTC |
| `updated_at` | date-time | Время последнего обновления в UTC |

Для `category` и `severity` используются фиксированные наборы значений. При создании необязательные поля по умолчанию получают `unknown`, пустую строку, `0` или пустой массив.

`PUT` реализован как полная замена редактируемой части ресурса. Поля, пропущенные в PUT-запросе, сбрасываются к значениям по умолчанию; `md5` и `created_at` сохраняются.

## Требования

- Go 1.23 или новее.
- Docker Desktop и Docker Compose — рекомендуемый способ запуска.
- Для локального запуска Go-процесса нужен доступный PostgreSQL 14+.

## Запуск всего приложения через Docker Compose

В корне проекта выполни:

```bash
docker compose up --build -d
```

Проверить контейнеры:

```bash
docker compose ps
```

Ожидаются два сервиса: `api` и `postgres`. PostgreSQL должен перейти в состояние `healthy`, API — в `Up`.

Посмотреть логи:

```bash
docker compose logs -f api
```

Проверить API:

```bash
curl -i http://localhost:8080/healthz
```

Ожидаемый ответ: `HTTP/1.1 200 OK` и `{"status":"ok"}`.

### Порты

| Компонент | Адрес | Назначение |
|---|---|---|
| Go API на хосте | `localhost:8080` | HTTP API |
| PostgreSQL на хосте | `localhost:5433` | Подключение из GoLand, psql и локальных инструментов |
| PostgreSQL внутри Compose | `postgres:5432` | Подключение API-контейнера к базе |

Внешний порт PostgreSQL задан как `5433:5432`, чтобы не конфликтовать с PostgreSQL, который может быть установлен непосредственно на macOS и уже занимать порт `5432`. Внутри Docker-сети API по-прежнему подключается к `postgres:5432`.

Остановить контейнеры, сохранив данные:

```bash
docker compose down
```

Остановить контейнеры и удалить хранилище PostgreSQL:

```bash
docker compose down -v
```

**Внимание:** `docker compose down -v` удаляет Docker volume с данными базы. Не используй эту команду, если данные нужно сохранить.

## Запуск Go API непосредственно из GoLand

Этот режим удобен для отладки исходного кода в IDE. PostgreSQL при этом можно оставить в Docker:

```bash
docker compose up -d postgres
```

Проверь, что PostgreSQL доступен на `localhost:5433`:

```bash
docker compose ps
```

Открой папку проекта в GoLand — ту, в которой находится `go.mod`. В терминале GoLand выполни:

```bash
go mod download
DATABASE_URL='postgres://threats:threats@localhost:5433/threats?sslmode=disable' go run ./cmd/api
```

Порт `5433` относится к подключению с macOS. Не используй его в `DATABASE_URL` API-контейнера: внутри Docker Compose адрес PostgreSQL — `postgres:5432`.

## Конфигурация

Пример переменных окружения находится в `.env.example`:

```bash
cp .env.example .env
```

Go-приложение само по себе не загружает `.env`: при локальном запуске добавь значения в Run Configuration GoLand или экспортируй их в shell. Docker Compose автоматически читает файл `.env` из корня проекта для подстановки переменных Compose.

| Переменная | Значение по умолчанию | Назначение |
|---|---|---|
| `HTTP_ADDR` | `:8080` | Адрес HTTP-сервера |
| `DATABASE_URL` | `postgres://threats:threats@localhost:5433/threats?sslmode=disable` в `.env.example` | Строка подключения PostgreSQL для локального Go-процесса |
| `API_KEY` | пусто | Если задан, все маршруты требуют заголовок `X-API-Key` |
| `RATE_LIMIT` | `120` | Число запросов с одного IP за минуту; `0` отключает ограничение |
| `TLS_CERT_FILE` | пусто | Путь к сертификату для локального HTTPS-запуска |
| `TLS_KEY_FILE` | пусто | Путь к приватному ключу; задаётся вместе с `TLS_CERT_FILE` |

В стандартном Docker Compose API использует внутренний DSN `postgres://threats:threats@postgres:5432/threats?sslmode=disable`. Пароль `threats` предназначен только для локальной демонстрации; перед реальным развёртыванием его необходимо заменить и хранить секреты вне репозитория.

### Проверка API Key

Включить API Key для Compose API-контейнера:

```bash
API_KEY='dev-test-secret' docker compose up -d --force-recreate api
```

Запрос без ключа должен вернуть `401 Unauthorized`:

```bash
curl -i http://localhost:8080/healthz
```

Запрос с ключом должен вернуть `200 OK`:

```bash
curl -i http://localhost:8080/healthz \
  -H 'X-API-Key: dev-test-secret'
```

Вернуть локальный режим без API Key:

```bash
API_KEY= docker compose up -d --force-recreate api
```

`dev-test-secret` — только демонстрационное значение. Не используй его в реальной среде и не коммить действительные секреты в Git.

### HTTPS / TLS

При локальном запуске Go-процесса HTTPS включается, если одновременно заданы `TLS_CERT_FILE` и `TLS_KEY_FILE`. Если задан только один из параметров, приложение завершится с ошибкой конфигурации. Стандартный Compose-файл не монтирует сертификаты в API-контейнер и запускает HTTP; для TLS в контейнерной среде нужно отдельно настроить безопасное подключение сертификатов или использовать reverse proxy.

## Примеры запросов

Для примеров используется MD5 `d41d8cd98f00b204e9800998ecf8427e`. Он нужен только как демонстрационный идентификатор.

### Создать угрозу

```bash
curl -i -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "name": "Trojan.Win32.Generic",
    "category": "malware",
    "severity": "high",
    "description": "Trojan that downloads additional payloads.",
    "family": "Generic",
    "confidence": 95,
    "source": "internal-sandbox",
    "tags": ["windows", "trojan"]
  }'
```

Успешный ответ — `201 Created`. В ответе также содержатся `created_at` и `updated_at`.

### Получить угрозу

```bash
curl -i http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

### Обновить угрозу

```bash
curl -i -X PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Trojan.Win32.Generic.v2",
    "category": "malware",
    "severity": "critical",
    "description": "Updated threat description",
    "family": "Generic",
    "confidence": 99,
    "source": "manual-analysis",
    "tags": ["windows", "trojan", "confirmed"]
  }'
```

Поскольку `PUT` полностью заменяет редактируемые поля, пропущенные поля будут сброшены к значениям по умолчанию.

## HTTP-коды

| Код | Условие |
|---|---|
| `200` | Получение или обновление успешно; также успешный healthcheck |
| `201` | Запись создана |
| `400` | Некорректный MD5, JSON или поля модели |
| `401` | `API_KEY` задан, но заголовок `X-API-Key` отсутствует или неверен |
| `404` | Угроза с таким MD5 не найдена |
| `409` | Угроза с таким MD5 уже существует |
| `413` | Тело запроса больше 1 MiB |
| `415` | `Content-Type` не равен `application/json` |
| `429` | Превышен rate limit; ответ содержит `Retry-After` |
| `500` | Внутренняя ошибка сервера |

Валидация JSON выполняется для `POST` и `PUT`; неизвестные поля отклоняются. Ограничение размера тела — 1 MiB.

## Тестирование

Unit-тесты без внешних сервисов:

```bash
go test ./...
```

Проверка гонок данных:

```bash
go test -race ./...
```

Покрытие:

```bash
go test -cover ./...
```

Статический анализ и сборка:

```bash
go vet ./...
go build ./cmd/api
```

### Интеграционный тест PostgreSQL

Интеграционный тест использует реальную PostgreSQL-базу. Для защиты данных тест отказывается работать с базой, имя которой не заканчивается на `_test`. Для каждой попытки генерируется случайный 32-символьный MD5; тест удаляет только созданную им запись.

Подними PostgreSQL:

```bash
docker compose up -d postgres
```

Создай отдельную базу:

```bash
docker compose exec postgres createdb -U threats threats_test
```

Запусти тест:

```bash
TEST_DATABASE_URL='postgres://threats:threats@localhost:5433/threats_test?sslmode=disable' \
  go test -race -cover ./internal/postgres -run '^TestPostgresRepositoryCRUD$' -count=1 -v
```

Или через Makefile:

```bash
make test-integration TEST_DATABASE_URL='postgres://threats:threats@localhost:5433/threats_test?sslmode=disable'
```

**Не указывай основную базу `threats` или production database в `TEST_DATABASE_URL`.** Тест проверяет имя базы и работает только с базой, имя которой оканчивается на `_test`.

## Структура проекта

```text
.
├── api/openapi.yaml
├── cmd/api/main.go
├── internal/
│   ├── config/config.go
│   ├── domain/
│   │   ├── threat.go
│   │   └── threat_test.go
│   ├── httpapi/
│   │   ├── handler.go
│   │   ├── handler_test.go
│   │   └── middleware.go
│   ├── postgres/
│   │   ├── migrations/001_create_threats.sql
│   │   ├── migrate.go
│   │   ├── postgres.go
│   │   └── postgres_integration_test.go
│   └── repository/
│       ├── memory.go
│       └── repository.go
├── .env.example
├── Dockerfile
├── Makefile
├── docker-compose.yml
├── go.mod
└── README.md
```

## Архитектура

HTTP-слой не содержит SQL и работает через интерфейс `ThreatRepository`. Доменный пакет отвечает за модель и валидацию. Для основного запуска используется PostgreSQL-реализация репозитория; HTTP-тесты используют потокобезопасную in-memory реализацию.

Rate limiter хранит счётчики в памяти процесса. Для нескольких реплик сервиса в production такой лимитер следует заменить общим хранилищем, например Redis, или вынести ограничение в API gateway. `X-Forwarded-For` намеренно не считается доверенным: при размещении за reverse proxy источник клиентского IP нужно настраивать отдельно.
