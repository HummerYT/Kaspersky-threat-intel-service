# Kaspersky Threat Intelligence Service

REST API сервис на Go для хранения и получения информации о файловых угрозах по MD5-хешу.

Сервис позволяет создавать записи об угрозах, получать информацию о них и обновлять существующие записи. Данные хранятся в PostgreSQL.

## Возможности

- Создание записи об угрозе.
- Получение информации об угрозе по MD5.
- Обновление существующей записи.
- Проверка состояния сервиса.
- Хранение данных в PostgreSQL.
- Автоматическое применение SQL-миграций при запуске.
- Проверка входных данных.
- Опциональная авторизация по API Key.
- Ограничение количества запросов.
- Поддержка HTTPS при локальном запуске с настроенными сертификатами.
- Unit-тесты и интеграционный тест PostgreSQL.
- Запуск приложения через Docker Compose.

## Используемые технологии

- Go
- PostgreSQL
- pgx/v5
- Docker
- Docker Compose
- OpenAPI 3.0

## Требования

Для запуска приложения понадобятся:

- Go 1.23 или новее.
- Docker Desktop.
- Docker Compose.

Для запуска Go-приложения без Docker потребуется отдельно установленный PostgreSQL.

## Запуск

Клонировать репозиторий:

```bash
git clone https://github.com/HummerYT/Kaspersky-threat-intel-service.git
cd Kaspersky-threat-intel-service
```

Создать файл конфигурации:

```bash
cp .env.example .env
```

Запустить приложение:

```bash
docker compose up --build -d
```

Проверить состояние контейнеров:

```bash
docker compose ps
```

Посмотреть логи API:

```bash
docker compose logs -f api
```

Проверить работоспособность сервиса:

```bash
curl http://localhost:8080/healthz
```

Ожидаемый ответ:

```json
{
  "status": "ok"
}
```

### Используемые порты

| Сервис | Адрес |
|---|---|
| API | `localhost:8080` |
| PostgreSQL | `localhost:5433` |

Внутри Docker Compose API подключается к PostgreSQL по адресу `postgres:5432`.

Остановить контейнеры, сохранив данные:

```bash
docker compose down
```

Команда `docker compose down -v` дополнительно удаляет том PostgreSQL вместе с данными.

## Конфигурация

Настройки приложения задаются через переменные окружения.

| Переменная | Назначение |
|---|---|
| `HTTP_ADDR` | Адрес HTTP-сервера |
| `DATABASE_URL` | Строка подключения к PostgreSQL |
| `API_KEY` | Ключ для авторизации запросов |
| `RATE_LIMIT` | Максимальное количество запросов с одного IP в минуту |
| `TLS_CERT_FILE` | Путь к TLS-сертификату |
| `TLS_KEY_FILE` | Путь к приватному TLS-ключу |

Если `API_KEY` не задан, проверка ключа отключена.

По умолчанию ограничение составляет 120 запросов в минуту с одного IP. Значение `0` отключает ограничение.

Для включения HTTPS необходимо одновременно указать `TLS_CERT_FILE` и `TLS_KEY_FILE`. В стандартной конфигурации Docker Compose используется HTTP.

При локальном запуске Go-приложения файл `.env` автоматически не загружается. Переменные необходимо передать через терминал или настройки запуска IDE.

## API

Полная спецификация API находится в файле [`api/openapi.yaml`](api/openapi.yaml).

### Доступные методы

| Метод | Endpoint | Описание |
|---|---|---|
| GET | `/healthz` | Проверка состояния сервиса |
| GET | `/info/{md5}` | Получение информации об угрозе |
| POST | `/info` | Создание записи |
| PUT | `/info/{md5}` | Обновление записи |

### Создание записи

Запрос:

```http
POST /info
Content-Type: application/json
```

Пример:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Trojan.Win32.Generic",
  "category": "malware",
  "severity": "high",
  "description": "Trojan that downloads additional payloads.",
  "family": "Generic",
  "confidence": 95,
  "source": "internal-sandbox",
  "tags": ["windows", "trojan"]
}
```

Успешный ответ: `201 Created`.

### Получение записи

Запрос:

```bash
curl http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

Успешный ответ: `200 OK`.

### Обновление записи

Запрос:

```http
PUT /info/d41d8cd98f00b204e9800998ecf8427e
Content-Type: application/json
```

Пример:

```json
{
  "name": "Trojan.Win32.Generic.v2",
  "category": "malware",
  "severity": "critical",
  "description": "Updated threat description",
  "family": "Generic",
  "confidence": 99,
  "source": "manual-analysis",
  "tags": ["windows", "trojan", "confirmed"]
}
```

Успешный ответ: `200 OK`.

`PUT` полностью заменяет редактируемые поля записи. Если поле не передано, оно получает значение по умолчанию. MD5 и дата создания сохраняются.

## Модель данных

| Поле | Тип | Описание |
|---|---|---|
| `md5` | string | MD5-хеш файла, 32 шестнадцатеричных символа |
| `name` | string | Название обнаружения |
| `category` | string | Категория угрозы |
| `severity` | string | Уровень опасности |
| `description` | string | Описание угрозы |
| `family` | string | Семейство вредоносного ПО |
| `confidence` | integer | Уверенность обнаружения от 0 до 100 |
| `source` | string | Источник информации |
| `tags` | string[] | Список тегов |
| `created_at` | date-time | Дата создания записи |
| `updated_at` | date-time | Дата обновления записи |

Допустимые категории:

- `unknown`
- `malware`
- `phishing`
- `ransomware`
- `exploit`
- `suspicious`

Допустимые уровни опасности:

- `unknown`
- `info`
- `low`
- `medium`
- `high`
- `critical`

MD5 является уникальным идентификатором записи.

## HTTP-коды ответов

| Код | Описание |
|---|---|
| `200` | Запрос выполнен успешно |
| `201` | Запись создана |
| `400` | Некорректные данные запроса |
| `401` | Отсутствует или неверен API Key |
| `404` | Запись не найдена |
| `409` | Запись с таким MD5 уже существует |
| `413` | Размер тела запроса превышает допустимый |
| `415` | Неподдерживаемый Content-Type |
| `429` | Превышено ограничение запросов |
| `500` | Внутренняя ошибка сервера |

## Тестирование

Запустить все тесты:

```bash
go test ./...
```

Запустить тесты с проверкой гонок данных:

```bash
go test -race ./...
```

Посмотреть покрытие тестами:

```bash
go test -cover ./...
```

Проверить код с помощью `go vet`:

```bash
go vet ./...
```

Собрать приложение:

```bash
go build ./cmd/api
```

### Интеграционный тест PostgreSQL

Для интеграционного теста используется отдельная база данных. Её имя обязательно должно заканчиваться на `_test`.

Запустить PostgreSQL:

```bash
docker compose up -d postgres
```

Создать тестовую базу:

```bash
docker compose exec postgres createdb -U threats threats_test
```

Запустить интеграционный тест:

```bash
TEST_DATABASE_URL='postgres://threats:threats@localhost:5433/threats_test?sslmode=disable' \
go test -race -cover ./internal/postgres -run '^TestPostgresRepositoryCRUD$' -count=1 -v
```

Тест проверяет основные операции с PostgreSQL. Он использует отдельный MD5 и удаляет созданную им запись после выполнения.

**Важно:** не указывайте основную или рабочую базу данных в `TEST_DATABASE_URL`.

## Дополнительно

- OpenAPI-спецификация: [`api/openapi.yaml`](api/openapi.yaml)
- Исходный код: [GitHub](https://github.com/HummerYT/Kaspersky-threat-intel-service)
