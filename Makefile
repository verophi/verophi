BINARY     := verophi
MODULE     := github.com/verophi/verophi
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
# BUILD_DATE is derived from the HEAD commit time (not wall-clock) so builds are
# reproducible. date -d works on GNU coreutils, date -r on BSD/macOS.
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
BUILD_DATE := $(shell date -u -d @$(SOURCE_DATE_EPOCH) +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -r $(SOURCE_DATE_EPOCH) +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -s -w \
	-X '$(MODULE)/internal/version_info.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version_info.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version_info.BuildDate=$(BUILD_DATE)'
GOFLAGS    := -trimpath -buildmode=pie

export GOTOOLCHAIN := local

.PHONY: help build install test test-unit test-property lint security gosec govulncheck verify coverage docker clean

## help: Show this help message
help:
	@echo "verophi — know which MR to merge first"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'

## build: Build verophi binary
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/verophi

## install: Install verophi to GOPATH/bin
install:
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/verophi

## test: Run all tests
test:
	go test -race -count=1 ./...

## test-unit: Run unit tests only
test-unit:
	go test -race -count=1 -run 'Test[^P]' ./...

## test-property: Run property-based tests only
test-property:
	go test -race -count=1 -run 'TestProperty' ./...

## lint: Run go vet + staticcheck
lint:
	go vet ./...
	@which staticcheck > /dev/null 2>&1 || { echo "staticcheck not installed. Run: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	staticcheck ./...

## security: Run gosec + govulncheck (both run independently)
security: gosec govulncheck

## gosec: Static security analysis
gosec:
	@which gosec > /dev/null 2>&1 || { echo "gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest"; exit 1; }
	gosec -quiet ./...

## govulncheck: Check dependencies for known vulnerabilities
govulncheck:
	@which govulncheck > /dev/null 2>&1 || { echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

## verify: Verify module checksums
verify:
	go mod verify

## coverage: Coverage report with 80% threshold
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@echo ""
	@total=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "Total coverage: $${total}%"; \
	if [ $$(echo "$${total} < 80.0" | bc -l) -eq 1 ]; then \
		echo "Coverage below 80% threshold"; exit 1; \
	else \
		echo "Coverage meets 80% threshold"; \
	fi

## docker: Build Docker images (build the static linux binaries first, then COPY them)
docker:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o verophi-amd64 ./cmd/verophi
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o verophi-arm64 ./cmd/verophi
	docker build -t ghcr.io/verophi/verophi -f Dockerfile .
	docker build -t ghcr.io/verophi/verophi-trivy -f Dockerfile.trivy .
	rm -f verophi-amd64 verophi-arm64

## build-all: Cross-compile for Linux and macOS
build-all:
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64   ./cmd/verophi
	GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-amd64  ./cmd/verophi
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64  ./cmd/verophi

## run-standalone: Run with bundled test data (no token needed)
run-standalone: build
	./bin/$(BINARY) analyze --sbom testdata/fixtures/sample-sbom.json

## clean: Remove build artifacts
clean:
	rm -rf bin/ coverage.out
