.PHONY: help proto build run test clean docker-up docker-down

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Protobuf generation
proto: ## Generate protobuf code
	~/go/bin/buf generate

# Build
build: proto ## Build the application
	go build -o bin/auth-service ./cmd/server

# Run services
run-grpc: build ## Run gRPC server only
	./bin/auth-service grpc

run-http: build ## Run HTTP server only
	./bin/auth-service http

run-all: build ## Run both gRPC and HTTP servers
	./bin/auth-service all

run: run-all ## Run both servers (default)

# Development
dev: ## Run in development mode with hot reload
	air

# Testing
test: ## Run tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Dependencies
deps: ## Download dependencies
	go mod download
	go mod tidy

# Linting
lint: ## Run linters
	golangci-lint run

# Clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf gen/
	rm -f coverage.out coverage.html

# Docker
docker-build: ## Build Docker image
	docker build -t auth-service-go .

docker-up: ## Start development environment
	docker-compose up -d

docker-down: ## Stop development environment
	docker-compose down

docker-logs: ## Show logs from development environment
	docker-compose logs -f

# Tools installation
install-tools: ## Install development tools
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install github.com/air-verse/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest