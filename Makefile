GO ?= go
BIN ?= bin/proxywatch

.PHONY: build test vet vulncheck check doctor fixture docker-build docker-doctor
build:
	mkdir -p $(dir $(BIN))
	CGO_ENABLED=1 $(GO) build -trimpath -o $(BIN) ./cmd/proxywatch

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# Reports known vulnerabilities reachable from ProxyWatch code.
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

check: test vet

doctor: build
	$(BIN) doctor

fixture: build
	$(BIN) discover --source fixtures --offline --db data/fixtures.db

docker-build:
	docker compose build

docker-doctor:
	docker compose run --rm proxywatch doctor
