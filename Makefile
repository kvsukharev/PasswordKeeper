BINARY_SERVER   := passwordkeeper-server
BINARY_CLIENT   := passwordkeeper
MODULE          := github.com/kvsuharev/passwordkeeper
BUILD_VERSION   ?= dev
BUILD_DATE      ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
BUILD_COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS         := -X main.buildVersion=$(BUILD_VERSION) \
                   -X main.buildDate=$(BUILD_DATE) \
                   -X main.buildCommit=$(BUILD_COMMIT)

PROTO_DIR       := api/proto
GEN_DIR         := api/gen
MIGRATIONS_DIR  := migrations
CERTS_DIR       := deploy/certs

GOBIN           ?= $(shell go env GOPATH)/bin
PROTOC_GEN_GO   := $(GOBIN)/protoc-gen-go
PROTOC_GEN_GRPC := $(GOBIN)/protoc-gen-go-grpc
GOLANGCI_LINT   := $(GOBIN)/golangci-lint

.PHONY: all build build-server build-client test test-integration cover lint proto certs \
        docker-up docker-down migrate clean tools

all: build

## build: compile server and client
build: build-server build-client

build-server:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_SERVER) ./cmd/server

build-client:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_CLIENT) ./cmd/client

## test: run unit tests (with race detector when CGO/gcc is available)
test:
	@if command -v gcc > /dev/null 2>&1; then \
		go test -race -count=1 ./...; \
	else \
		echo "Warning: gcc not found, running tests without -race"; \
		go test -count=1 ./...; \
	fi

## test-integration: run integration tests (requires Docker)
test-integration:
	go test -tags integration -count=1 -timeout 120s ./internal/server/storage/...

## cover: run tests and check coverage ≥ 70%
cover:
	go test -count=1 -coverprofile=coverage.out \
		$(shell go list ./... | grep -v '/api/gen' | grep -v 'cmd/' | grep -v 'internal/server/storage$$')
	go tool cover -func=coverage.out
	@awk '/^total:/{gsub("%",""); if ($$3+0 < 70) {print "Coverage " $$3 "% is below 70%"; exit 1}}' coverage.out

## lint: run golangci-lint
lint:
	$(GOLANGCI_LINT) run ./...

## proto: generate Go code from .proto files using buf
proto:
	buf generate

## certs: generate self-signed TLS certificates for development
certs:
	bash $(CERTS_DIR)/gen-certs.sh $(CERTS_DIR)

## docker-up: start PostgreSQL and server via docker-compose
docker-up:
	docker compose -f deploy/docker-compose.yml up -d

## docker-down: stop containers
docker-down:
	docker compose -f deploy/docker-compose.yml down

## migrate: run database migrations (requires DATABASE_URL env)
migrate:
	go run ./cmd/server migrate

## tools: install required Go tools
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install go.uber.org/mock/mockgen@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
		sh -s -- -b $(GOBIN) v1.61.0

## release: cross-compile client binaries for all platforms
release:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)_linux_amd64   ./cmd/client
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)_linux_arm64   ./cmd/client
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)_darwin_amd64  ./cmd/client
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)_darwin_arm64  ./cmd/client
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)_windows_amd64.exe ./cmd/client

## clean: remove build artifacts
clean:
	rm -rf bin/ dist/ coverage.out
