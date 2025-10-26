# Stateless Multi-Realm Auth Service with OpenTelemetry

A **production-ready, stateless authentication service** built in Go that acts as an intelligent API gateway for Keycloak. This service provides both gRPC and REST API interfaces with **dynamic realm and client configuration** per request, eliminating the need for database dependencies.

## 🚀 Key Features

- **🌐 Stateless Architecture**: No database dependencies - Keycloak is the single source of truth
- **🔄 Multi-Realm Support**: Apps can specify any realm dynamically per request
- **🔐 Flexible Client Management**: Different client credentials per request
- **📡 Pure API Gateway**: Intelligent proxy pattern for Keycloak operations
- **⚡ Horizontal Scalability**: No server-side state for unlimited scaling
- **🔍 Dual Interface**: Both gRPC and REST API support
- **📊 OpenTelemetry Tracing**: Full distributed tracing across all service boundaries
- **⚡ Redis Caching**: Intelligent caching for tokens and user data
- **🏥 Health Monitoring**: Comprehensive health checks and Prometheus metrics
- **🛡️ Production Ready**: Enterprise-grade error handling and graceful shutdown

## 🎯 Architecture Overview

This service transforms traditional authentication patterns by:

- **Eliminating Database Dependencies**: All user data lives in Keycloak
- **Dynamic Realm Routing**: Each request specifies its target realm
- **Stateless Operation**: Perfect for microservices and cloud-native deployments
- **Client Flexibility**: Support multiple applications with different client configurations

## 📋 Prerequisites

- Go 1.25 or later
- Redis server (for caching)
- Keycloak server (single source of truth)
- OpenTelemetry Collector (optional, for trace collection)

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/laithalenooz/auth-service-go.git
cd auth-service-go
```

### 2. Install Dependencies
```bash
go mod tidy
```

### 3. Configuration
Copy the example environment file and configure it:
```bash
cp .env.example .env
```

Edit `.env` with your settings:
```env
# Service Configuration
SERVICE_NAME=auth-service
SERVICE_VERSION=1.0.0
SERVICE_ENVIRONMENT=development

# Server Configuration
HTTP_PORT=8080
GRPC_PORT=8081

# Keycloak Configuration (Default/Fallback)
KEYCLOAK_BASE_URL=http://localhost:8090
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=auth-service
KEYCLOAK_CLIENT_SECRET=hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# OpenTelemetry Configuration
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_SERVICE_NAME=auth-service
OTEL_SERVICE_VERSION=1.0.0
```

### 4. Build the Application
```bash
make build
# or
go build -o bin/auth-service ./cmd/server
```

## 🏃‍♂️ Running the Service

### Option 1: Run Both gRPC and HTTP Servers (Default)
```bash
./bin/auth-service
# or
./bin/auth-service all
```

### Option 2: Run Only gRPC Server
```bash
./bin/auth-service grpc
```

### Option 3: Run Only HTTP Server
```bash
./bin/auth-service http
```

### Using Make Commands
```bash
# Build and run all services
make run

# Development with hot reload
make dev
```

## 🌐 REST API Endpoints

The HTTP server runs on port `8080` by default and provides the following REST endpoints:

### Health & Monitoring
- `GET /health` - Service health check (cached)
- `GET /health/detailed` - Detailed health check (real-time)
- `GET /ready` - Kubernetes readiness probe
- `GET /live` - Kubernetes liveness probe
- `GET /metrics` - Prometheus metrics

### Authentication Operations
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/reset-password` - Password reset initiation

### User Management
- `POST /api/v1/users` - Create a new user
- `GET /api/v1/users/{id}` - Get user by ID
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user
- `GET /api/v1/users` - List users (with pagination)

### Token Operations
- `POST /api/v1/tokens/introspect` - Introspect a token
- `POST /api/v1/tokens/refresh` - Refresh a token

## 📝 API Usage Examples

### 🔐 Authentication Operations

#### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

#### Register User
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "first_name": "New",
    "last_name": "User",
    "password": "password123",
    "email_verified": false
  }'
```

#### Logout
```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your-refresh-token"
  }'
```

### 👥 User Management Operations

#### Create User
```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "enabled": true,
    "email_verified": true
  }'
```

#### Get User (Using Headers)
```bash
curl -X GET http://localhost:8080/api/v1/users/{user-id} \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK"
```

#### Update User
```bash
curl -X PUT http://localhost:8080/api/v1/users/{user-id} \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated",
    "last_name": "Name",
    "enabled": true
  }'
```

### 🔑 Token Operations

#### Introspect Token
```bash
curl -X POST http://localhost:8080/api/v1/tokens/introspect \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your-jwt-token",
    "token_type_hint": "access_token"
  }'
```

#### Refresh Token
```bash
curl -X POST http://localhost:8080/api/v1/tokens/refresh \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: auth-service" \
  -H "X-Client-Secret: hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your-refresh-token"
  }'
```

## 🔧 gRPC Interface

The gRPC server runs on port `8081` by default. All gRPC methods now require realm and client parameters:

### Using grpcurl
```bash
# List available services
grpcurl -plaintext localhost:8081 list

# Call health check
grpcurl -plaintext localhost:8081 keycloak.v1.KeycloakService/HealthCheck

# Login user
grpcurl -plaintext -d '{
  "realm_name": "master",
  "username": "admin",
  "password": "admin",
  "client_id": "auth-service",
  "client_secret": "hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK"
}' localhost:8081 keycloak.v1.KeycloakService/Login

# Create user
grpcurl -plaintext -d '{
  "realm_name": "master",
  "client_id": "auth-service",
  "client_secret": "hejd9wWpPdp4fmFYFjGwU7dBJErTWQaK",
  "username": "jane.doe",
  "email": "jane.doe@example.com",
  "enabled": true
}' localhost:8081 keycloak.v1.KeycloakService/CreateUser
```

## 🌟 Multi-Realm Usage Examples

The service supports multiple realms and clients dynamically:

### Different Realm Example
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "X-Realm-Name: company-realm" \
  -H "X-Client-Id: company-app" \
  -H "X-Client-Secret: company-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "employee",
    "password": "password"
  }'
```

### Different Client Example
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "X-Realm-Name: master" \
  -H "X-Client-Id: mobile-app" \
  -H "X-Client-Secret: mobile-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mobileuser",
    "email": "mobile@example.com",
    "password": "mobilepass"
  }'
```

## 📊 Observability & Monitoring

### OpenTelemetry Tracing
The service automatically instruments:
- HTTP requests (Gin middleware)
- gRPC calls (otelgrpc interceptors)
- Keycloak HTTP client calls
- Redis operations
- Internal service operations
- **Realm-specific tracing** with dynamic attributes

### Prometheus Metrics
Comprehensive metrics available at `/metrics` endpoint:
```bash
curl http://localhost:8080/metrics
```

**Key Metrics:**
- Request duration and count by realm/client
- Authentication success/failure rates
- Cache hit/miss ratios
- Health check status
- gRPC and HTTP request metrics

### Health Monitoring
- **Cached Health Check**: `GET /health` (fast response)
- **Detailed Health Check**: `GET /health/detailed` (real-time status)
- **Kubernetes Probes**: `/ready` and `/live` endpoints
- **Dependency Monitoring**: Keycloak and Redis health tracking

## 🐳 Development with Docker

Complete development environment with monitoring stack:

```yaml
version: '3.8'
services:
  # Core Services
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
  
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_HEALTH_ENABLED: true
    ports:
      - "8090:8080"
    command: start-dev
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health/ready || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Observability Stack
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "4317:4317"
      - "4318:4318"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./docker/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./docker/grafana/provisioning:/etc/grafana/provisioning
      - ./docker/grafana/dashboards:/var/lib/grafana/dashboards
```

Start the complete development environment:
```bash
docker-compose up -d
```

## 🧪 Testing

### Run Tests
```bash
make test
# or
go test -v ./...
```

### Test Coverage
```bash
make test-coverage
```

### Integration Testing
```bash
# Test with different realms and clients
./scripts/test-service.sh
```

## 🔨 Development Commands

```bash
# Generate protobuf code
make proto
# or
buf generate

# Build the application
make build

# Run with hot reload
make dev

# Run linting
make lint

# Clean build artifacts
make clean

# Install development tools
make install-tools
```

## 📁 Project Structure

```
auth-service-go/
├── cmd/server/              # Application entry point
├── internal/
│   ├── cache/              # Redis caching with tracing
│   ├── config/             # Configuration management
│   ├── health/             # Health check system
│   ├── keycloak/           # Stateless Keycloak client
│   ├── metrics/            # Prometheus metrics
│   ├── middleware/         # HTTP/gRPC middleware
│   ├── server/             # gRPC server implementation
│   └── telemetry/          # OpenTelemetry setup
├── proto/                  # Protocol buffer definitions
├── gen/                    # Generated protobuf code
├── postman/                # Postman collection & environment
├── docker/                 # Docker configurations
│   ├── grafana/           # Grafana dashboards & config
│   ├── prometheus/        # Prometheus configuration
│   └── otel/              # OpenTelemetry collector config
├── docs/                   # Documentation
├── scripts/                # Utility scripts
├── .env.example           # Environment configuration template
└── Makefile               # Development commands
```

## 🚀 Production Deployment

### Environment Variables
```env
# Production Configuration
SERVICE_ENVIRONMENT=production
HTTP_PORT=8080
GRPC_PORT=8081

# Keycloak (Base URL only - realms specified per request)
KEYCLOAK_BASE_URL=https://keycloak.yourdomain.com

# Redis (Production)
REDIS_URL=redis://redis.yourdomain.com:6379/0

# OpenTelemetry (Production)
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.yourdomain.com:4317
OTEL_SERVICE_NAME=auth-service
OTEL_SERVICE_VERSION=1.0.0
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        ports:
        - containerPort: 8080
        - containerPort: 8081
        env:
        - name: SERVICE_ENVIRONMENT
          value: "production"
        livenessProbe:
          httpGet:
            path: /live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 🔒 Security Considerations

- **No Stored Secrets**: Client secrets are provided per request
- **Stateless Design**: No session storage or user data persistence
- **Realm Isolation**: Each request operates in its specified realm
- **Audit Logging**: All operations traced via OpenTelemetry
- **Health Monitoring**: Continuous dependency health checking

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Run linting and tests
7. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🎉 What's New in v2.0

### 🚀 Major Architecture Transformation
- **Stateless Design**: Eliminated all database dependencies
- **Multi-Realm Support**: Dynamic realm specification per request
- **Flexible Client Management**: Different clients per request
- **Pure API Gateway**: Intelligent Keycloak proxy pattern

### 🔧 Breaking Changes
- All API requests now require `X-Realm-Name`, `X-Client-Id`, and `X-Client-Secret` headers
- GET requests use headers for realm/client parameters
- POST requests include parameters in headers (not body)
- Server configuration no longer defines default realm/client
- Field names use snake_case format (e.g., `refresh_token`, `token_type_hint`)

### 📈 Performance Improvements
- Horizontal scalability with no server-side state
- Intelligent caching with realm-specific keys
- Enhanced tracing with realm/client context
- Optimized for cloud-native deployments

**Migration Guide**: Update your API calls to include realm and client parameters in headers as shown in the examples above. Ensure all field names use snake_case format (e.g., `refresh_token` instead of `refreshToken`).