.PHONY: compare-wireshark record-interop help all test coverage cover lint lint-ci vuln fmt fmt-check vet mod-check targets cross static fuzz golden bench build check clean coverage-check coverage-pkg-check docs-check

# Prefer module-local dependency resolution when a sibling go.work exists.
export GOWORK := off

help: ## Show targets and descriptions
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

APP_NAME   = mmstracectl
# The CLI is a nested module: ./... of this module does not reach it.
CLI_DIR    = cmd/mmstracectl
GO_CLI     = go -C $(CLI_DIR)
BIN_DIR    = bin
BINARY     = $(BIN_DIR)/$(APP_NAME)

# Version and tag only when HEAD is exactly on a tag (version without the leading v);
# otherwise the binary reports dev. The full commit SHA, as the Release workflow injects.
VERSION    ?= $(patsubst v%,%,$(shell git describe --tags --exact-match 2>/dev/null))
TAG        ?= $(shell git describe --tags --exact-match 2>/dev/null || echo "")
# -dirty when the working tree has changes, as Go itself marks vcs.modified
# (git status --porcelain, untracked files included); empty outside git.
DIRTY := $(shell [ -z "$$(git status --porcelain 2>/dev/null)" ] || echo -dirty)
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")$(DIRTY)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-s -w -X 'main.version=$(VERSION)' -X 'main.tag=$(TAG)' -X 'main.commit=$(COMMIT)' -X 'main.buildDate=$(BUILD_DATE)'"

# CI formats with the Go version from go.mod; gofmt output can differ between releases.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

# Every target builds with CGO_ENABLED=0.
TARGETS = linux/amd64 linux/arm64 linux/arm darwin/arm64 darwin/amd64 windows/amd64 windows/arm64

# Same minimum as coverage-min in ci.yml.
COVER_MIN := 90
# Per-package floor.
COVER_PKG_MIN := 85
# Fuzz targets and the time each gets in `make fuzz`.
FUZZ_TIME ?= 30s
FUZZ_TARGETS = ./internal/pcapio:FuzzPcapReader ./internal/pcapio:FuzzPcapngReader ./internal/link:FuzzLinkIPTCP \
	./trace:FuzzAnalyze

# docsync release of docs-check.
DOCSYNC_VERSION := v0.3.1

all: check build ## Run checks and build bin/mmstracectl

check: fmt fmt-check mod-check lint lint-ci vet vuln test coverage-check coverage-pkg-check targets docs-check ## Format, lint, vet, vuln, test, coverage, cross-build and check the docs

test: ## Run unit tests (race detector), library and cmd/mmstracectl
	@echo "Running go test -race ./..."
	@go test -count=1 -race ./...
	@cd $(CLI_DIR) && go test -count=1 -race ./...

coverage: ## Write coverage.out (atomic mode; -coverpkg=./... as in ci.yml)
	@echo "Running tests with coverage"
	@go test -count=1 -race -coverpkg=./... -coverprofile=coverage.out -covermode=atomic ./...

coverage-check: coverage ## Fail when total coverage is below COVER_MIN
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t+0 < m+0) { printf "coverage %.1f%% < %s%%\n", t, m; exit 1 } else printf "coverage %.1f%% >= %s%%\n", t, m }'

coverage-pkg-check: coverage ## Fail when a package is below COVER_PKG_MIN
	@awk -v m="$(COVER_PKG_MIN)" 'NR > 1 { n[$$1] = $$2; if ($$3 > 0) h[$$1] = 1 } \
	END { for (k in n) { p = k; sub(/\/[^\/]*$$/, "", p); s[p] += n[k]; if (k in h) c[p] += n[k] } \
	for (p in s) { v = 100 * c[p] / s[p]; if (v < m) { printf "%s: %.1f%% < %s%%\n", p, v, m; bad = 1 } else printf "%s: %.1f%%\n", p, v } exit bad }' coverage.out

cover: coverage ## Open HTML coverage report
	@go tool cover -html=coverage.out

fuzz: ## Run every fuzz target for FUZZ_TIME
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t#*:}; \
		echo "Fuzzing $$name in $$pkg for $(FUZZ_TIME)"; \
		go test -run '^$$' -fuzz "^$$name$$" -fuzztime $(FUZZ_TIME) $$pkg || exit 1; \
	done

golden: ## Regenerate testdata/*.pcap from real go-mms associations, then the CLI's golden outputs
	@go test -count=1 -run TestFixture ./trace -update
	@cd $(CLI_DIR) && go test -count=1 -run TestGolden . -update

bench: ## Run benchmarks
	@go test -run '^$$' -bench . -benchmem ./...

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck ./...
	@cd $(CLI_DIR) && staticcheck ./...

lint-ci: ## Run golangci-lint (.golangci.yml)
	@echo "Running golangci-lint"
	@golangci-lint run ./...
	@cd $(CLI_DIR) && golangci-lint run ./...

fmt: ## gofmt all Go sources with the go.mod Go version
	@echo "Running gofmt (go$(GO_MOD_VERSION))"
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if the go.mod-version gofmt or the local gofmt would change any file
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then echo "Not formatted:"; echo "$$ci $$loc"; exit 1; fi

mod-check: ## Fail on a replace directive or a local path in the library's go.mod
	@if grep -nE '^[[:space:]]*replace|=>' go.mod; then echo "go.mod must not contain replace directives"; exit 1; fi

vet: ## go vet
	@go vet ./...
	@cd $(CLI_DIR) && go vet ./...

vuln: ## Run govulncheck
	@govulncheck ./...
	@cd $(CLI_DIR) && govulncheck ./...

targets: ## Cross-build every package for every target with CGO_ENABLED=0
	@for t in $(TARGETS); do \
		echo "Building $$t"; \
		GOOS=$${t%/*} GOARCH=$${t#*/} GOARM=7 CGO_ENABLED=0 go build ./... || exit 1; \
		(cd $(CLI_DIR) && GOOS=$${t%/*} GOARCH=$${t#*/} GOARM=7 CGO_ENABLED=0 go build -o "$(CURDIR)/$(BIN_DIR)/targets/$$t/" ./...) || exit 1; \
	done

cross: targets ## Alias of targets

static: ## Build mmstracectl for Linux and check that it is statically linked
	@mkdir -p $(BIN_DIR)
	@for a in amd64 arm64 arm; do \
		GOOS=linux GOARCH=$$a GOARM=7 CGO_ENABLED=0 $(GO_CLI) build -trimpath $(LDFLAGS) -o "$(CURDIR)/$(BIN_DIR)/$(APP_NAME)-linux-$$a" . || exit 1; \
		file $(BIN_DIR)/$(APP_NAME)-linux-$$a | grep -q 'statically linked' || { file $(BIN_DIR)/$(APP_NAME)-linux-$$a; exit 1; }; \
		echo "$(APP_NAME)-linux-$$a: static"; \
	done

build: ## Build $(BINARY) (static)
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=0 $(GO_CLI) build $(LDFLAGS) -o "$(CURDIR)/$(BINARY)" .

# The documents against the code: docsync, as docs.yml runs it.
docs-check: ## Check that the documents agree with the code (docsync), library and cmd/mmstracectl
	@go run github.com/otfabric/docsync@$(DOCSYNC_VERSION) check .
	@cd $(CLI_DIR) && go run github.com/otfabric/docsync@$(DOCSYNC_VERSION) check .

clean: ## Remove bin/ and coverage.out
	@rm -rf $(BIN_DIR) coverage.out

compare-wireshark: build ## Compare every MMS PDU of the test captures with Wireshark's dissector (needs tshark)
	@python3 scripts/compare-wireshark.py --port 1102 --mmstracectl $(BINARY) testdata/captures/interop/*.pcap
	@find testdata/captures/public -type f ! -name '*.json' ! -name '*.md' ! -name SHA256SUMS -print0 | sort -z | \
		xargs -0 python3 scripts/compare-wireshark.py --mmstracectl $(BINARY)

record-interop: ## Record captures between the independent stacks of iec61850-interop (needs Docker; OUT=dir)
	@scripts/record-interop.sh $(or $(OUT),testdata/captures/interop)
