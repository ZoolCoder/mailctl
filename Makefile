BIN := bin/mailctl
PKG := ./...
# local builds carry the git version with a -dev suffix
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')-dev
LDFLAGS := -X github.com/zoolcoder/mailctl/internal/cli.Version=$(VERSION)

.PHONY: build run test test-unit lint fmt clean install ui docs docs-serve evals

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/mailctl

run: build
	$(BIN) $(ARGS)

ui: build
	$(BIN) ui

test:
	go test $(PKG)

test-unit:
	go test -short $(PKG)

lint:
	go vet $(PKG)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, go vet only"

fmt:
	gofmt -l -w cmd internal

install: build
	mkdir -p $(HOME)/.local/bin
	cp $(BIN) $(HOME)/.local/bin/mailctl.new
	mv $(HOME)/.local/bin/mailctl.new $(HOME)/.local/bin/mailctl
	@echo "installed $(VERSION) to ~/.local/bin/mailctl (add to PATH if needed)"

evals: ## run the plugin eval suite (evals/), needs the claude CLI
	claude plugin eval . --no-publish --threshold 0.8

docs:
	[ -d node_modules ] || npm ci
	npm run docs

docs-serve: docs
	npx --yes http-server build/site -p 8080 -c-1

clean:
	rm -rf bin dist build
