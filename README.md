# Keycloak Wrapper Microservice with OpenTelemetry

A production-ready Keycloak wrapper microservice built in Go with comprehensive OpenTelemetry distributed tracing. This service provides both gRPC and REST API interfaces for Keycloak user management and token operations.

## 🚀 Features

- **Dual Interface**: Both gRPC and REST API support
- **OpenTelemetry Tracing**: Full distributed tracing across all service boundaries
- **Redis Caching**: Intelligent caching for tokens, JWKS, and user data
- **Keycloak Integration**: Complete user management and token operations
- **Health Monitoring**: Health checks and Prometheus metrics
- **Production Ready**: Comprehensive error handling and graceful shutdown

## 📋 Prerequisites

- Go 1.25 or later
- Redis server
- Keycloak server
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
# OpenTelemetry Configuration
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_SERVICE_NAME=keycloak-wrapper
OTEL_SAMPLING_RATIO=0.01

# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Service Configuration
GRPC_PORT=9090
HTTP_PORT=8080
ENVIRONMENT=development
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
make run-all

# Run only gRPC server
make run-grpc

# Run only HTTP gateway
make run-gateway
```

## 🌐 REST API Endpoints

The HTTP server runs on port `8080` by default and provides the following REST endpoints:

### Health & Monitoring
- `GET /health` - Service health check
- `GET /metrics` - Prometheus metrics

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

### Create User
```bash
curl -X POST http://localhost:8080/api/v1/users \
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

### Get User
```bash
curl http://localhost:8080/api/v1/users/{user-id}
```

### Introspect Token
```bash
curl -X POST http://localhost:8080/api/v1/tokens/introspect \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your-jwt-token",
    "token_type_hint": "access_token"
  }'
```

### Health Check
```bash
curl http://localhost:8080/health
```

## 🔧 gRPC Interface

The gRPC server runs on port `9090` by default. You can use any gRPC client to interact with it:

### Using grpcurl
```bash
# List available services
grpcurl -plaintext localhost:9090 list

# Call health check
grpcurl -plaintext localhost:9090 keycloak.v1.KeycloakService/HealthCheck

# Create user
grpcurl -plaintext -d '{
  "username": "jane.doe",
  "email": "jane.doe@example.com",
  "enabled": true
}' localhost:9090 keycloak.v1.KeycloakService/CreateUser
```

## 📊 Observability

### OpenTelemetry Tracing
The service automatically instruments:
- HTTP requests (Gin middleware)
- gRPC calls (otelgrpc interceptors)
- Keycloak HTTP client calls
- Redis operations
- Internal service operations

### Metrics
Prometheus metrics are available at `/metrics` endpoint:
```bash
curl http://localhost:8080/metrics
```

### Trace Visualization
Configure your OpenTelemetry Collector to send traces to Jaeger, Zipkin, or any compatible backend.

## 🐳 Development with Docker

Create a `docker-compose.yml` for local development:

```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
  
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    command: start-dev
  
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "4317:4317"
      - "4318:4318"
```

Start the development environment:
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

## 🔨 Development Commands

```bash
# Generate protobuf code
make proto

# Build the application
make build

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
├── cmd/server/           # Application entry point
├── internal/
│   ├── cache/           # Redis caching with tracing
│   ├── config/          # Configuration management
│   ├── keycloak/        # Keycloak client with tracing
│   ├── server/          # gRPC server implementation
│   └── telemetry/       # OpenTelemetry setup
├── proto/               # Protocol buffer definitions
├── gen/                 # Generated protobuf code
├── .env.example         # Environment configuration template
└── Makefile            # Development commands
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run linting and tests
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.