.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

GOLANGCI_LINT_VERSION := v2.11.3

.PHONY: lint
lint: ## Run linters
	@golangci-lint --version 2>/dev/null | grep -q $(GOLANGCI_LINT_VERSION) || \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	golangci-lint run

.PHONY: test
test: ## Run all tests with race detector
	go test -race ./...

.PHONY: build
build: ## Build the Go binary
	go build -o bin/server ./cmd

.PHONY: run
run: ## Run the server locally
	go run ./cmd

.PHONY: ci
ci: lint test ## Run lint and tests (CI pipeline)

# Test