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
	~/go/bin/air

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
	docker build -t auth-service-go:latest .

docker-build-prod: ## Build production Docker image with version tag
	docker build -t auth-service-go:$(shell git rev-parse --short HEAD) -t auth-service-go:latest .

docker-run: ## Run Docker container locally
	docker run --rm -p 8080:8080 -p 8081:8081 --name auth-service auth-service-go:latest

docker-up: ## Start development environment
	docker-compose up -d

docker-down: ## Stop development environment
	docker-compose down

docker-logs: ## Show logs from development environment
	docker-compose logs -f

docker-clean: ## Clean Docker images and containers
	docker system prune -f
	docker rmi auth-service-go:latest 2>/dev/null || true

# Production Docker commands
docker-up-prod: ## Start production environment
	docker-compose -f docker-compose.prod.yml up -d

docker-down-prod: ## Stop production environment
	docker-compose -f docker-compose.prod.yml down

docker-logs-prod: ## Show logs from production environment
	docker-compose -f docker-compose.prod.yml logs -f

# Complete deployment commands
deploy-dev: docker-build docker-up ## Build and deploy development environment

deploy-prod: docker-build-prod docker-up-prod ## Build and deploy production environment

# Troubleshooting commands
fix-keycloak: ## Fix common Keycloak startup issues
	./scripts/fix-keycloak.sh

fix-keycloak-import: ## Fix Keycloak import conflicts (clean start)
	docker-compose down -v
	docker volume rm auth-service-go_postgres-data auth-service-go_keycloak-data 2>/dev/null || true
	./scripts/fix-keycloak.sh

docker-logs-keycloak: ## Show Keycloak logs
	docker-compose logs -f keycloak

docker-logs-postgres: ## Show PostgreSQL logs
	docker-compose logs -f postgres

docker-restart-keycloak: ## Restart only Keycloak service
	docker-compose restart keycloak

docker-clean-all: ## Clean all Docker resources (containers, volumes, images)
	docker-compose down -v
	docker system prune -af
	docker volume prune -f

# Testing commands
test-reset-password: ## Test reset password functionality
	./scripts/test-reset-password.sh

test-impersonation: ## Test user impersonation functionality
	./scripts/test-impersonation.sh

test-keycloak-direct: ## Test Keycloak API directly (for debugging)
	./scripts/test-keycloak-direct.sh

test-service: ## Test all service endpoints
	./scripts/test-service.sh

# Build without Docker (requires local Go and buf installation)
build-local: proto ## Build application locally (requires Go and buf)
	CGO_ENABLED=0 go build -ldflags='-w -s' -o bin/auth-service ./cmd/server

build-local-with-tools: install-tools build-local ## Install tools and build locally

# Tools installation
install-tools: ## Install development tools
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install github.com/air-verse/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest