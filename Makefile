.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

.PHONY: lint
lint: ## Run linters
	golangci-lint run

.PHONY: build
build: ## Build the Go binary
	go build -o bin/server ./cmd

.PHONY: run
run: ## Run the server locally
	go run ./cmd