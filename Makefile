.PHONY: run test test-race test-cover test-integration build fmt vet docker-up docker-down docker-logs

GO ?= go
DOCKER_COMPOSE ?= docker compose

run:
	$(GO) run ./cmd/api

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-cover:
	$(GO) test -cover ./...

# TEST_DATABASE_URL must point to a dedicated database whose name ends in _test.
# The integration test checks this before applying migrations or writing data.
test-integration:
	@test -n "$(TEST_DATABASE_URL)" || (echo "Set TEST_DATABASE_URL to a dedicated *_test database" >&2; exit 1)
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" $(GO) test ./internal/postgres -run '^TestPostgresRepositoryCRUD$$' -count=1 -v

build:
	@mkdir -p bin
	$(GO) build -o bin/threat-api ./cmd/api

fmt:
	gofmt -w ./cmd ./internal

vet:
	$(GO) vet ./...

docker-up:
	$(DOCKER_COMPOSE) up --build -d

docker-down:
	$(DOCKER_COMPOSE) down

docker-logs:
	$(DOCKER_COMPOSE) logs -f --tail=100
