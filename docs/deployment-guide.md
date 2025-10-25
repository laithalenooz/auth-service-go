# Auth Service - Deployment & Testing Guide

This guide provides step-by-step instructions for running the Auth Service with all its dependencies and testing the complete functionality.

## 🚀 Quick Start

### Prerequisites

- **Docker & Docker Compose**: Latest version
- **Go**: Version 1.21+ (for development)
- **Postman**: For API testing (optional)
- **Git**: For cloning the repository

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd auth-service-go

# Copy environment configuration
cp .env.example .env

# Edit .env file with your specific configuration
nano .env
```

### 2. Start the Complete Stack

```bash
# Start all services (Keycloak, Redis, Prometheus, Grafana, Jaeger, etc.)
docker-compose up -d

# Wait for services to be ready (about 2-3 minutes)
docker-compose logs -f keycloak  # Wait for "Started" message

# Build and run the Auth Service
make run
```

## 📋 Service Architecture

### Core Services

| Service | Port | Purpose | Health Check |
|---------|------|---------|--------------|
| **Auth Service** | 8080 (HTTP), 8081 (gRPC) | Main application | `http://localhost:8080/health` |
| **Keycloak** | 8090 | Identity Provider | `http://localhost:8090/health` |
| **Redis** | 6379 | Cache & Session Store | `redis-cli ping` |
| **Prometheus** | 9090 | Metrics Collection | `http://localhost:9090/-/healthy` |
| **Grafana** | 3000 | Metrics Visualization | `http://localhost:3000/api/health` |
| **Jaeger** | 16686 | Distributed Tracing | `http://localhost:16686` |

### Monitoring Stack

| Component | URL | Credentials |
|-----------|-----|-------------|
| **Grafana Dashboards** | http://localhost:3000 | admin/admin |
| **Prometheus Metrics** | http://localhost:9090 | None |
| **Jaeger Tracing** | http://localhost:16686 | None |
| **Auth Service Metrics** | http://localhost:8080/metrics | None |

## 🔧 Configuration

### Environment Variables

Key configuration in `.env`:

```bash
# Service Configuration
SERVICE_NAME=auth-service
SERVICE_VERSION=1.0.0
SERVICE_ENVIRONMENT=development

# Server Ports
HTTP_PORT=8080
GRPC_PORT=8081

# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8090
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=auth-service
KEYCLOAK_CLIENT_SECRET=your-secret-here
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# OpenTelemetry Configuration
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_SERVICE_NAME=auth-service
OTEL_SERVICE_VERSION=1.0.0
```

### Keycloak Setup

1. **Access Keycloak Admin Console**:
   - URL: http://localhost:8090
   - Username: `admin`
   - Password: `admin`

2. **Create Client for Auth Service**:
   ```bash
   # Client ID: auth-service
   # Client Protocol: openid-connect
   # Access Type: confidential
   # Service Accounts Enabled: ON
   # Authorization Enabled: ON
   ```

3. **Configure Client Credentials**:
   - Go to Credentials tab
   - Copy the Secret
   - Update `KEYCLOAK_CLIENT_SECRET` in `.env`

## 🏃‍♂️ Running the Service

### Development Mode (Hot Reload)

```bash
# Install Air for hot reload (if not already installed)
go install github.com/air-verse/air@latest

# Start with hot reload
make dev

# Or manually
air
```

### Production Mode

```bash
# Build the application
make build

# Run specific components
make run-grpc    # gRPC server only
make run-http    # HTTP server only  
make run         # Both servers (default)
```

### Docker Mode

```bash
# Build Docker image
docker build -t auth-service .

# Run with Docker Compose
docker-compose up auth-service
```

## 🧪 Testing with Postman

### 1. Import Collection

1. Open Postman
2. Click **Import**
3. Select `postman/Auth-Service-Collection.json`
4. Collection will be imported with all test cases

### 2. Configure Variables

Update collection variables:
- `base_url`: `http://localhost:8080`
- `keycloak_client_id`: Your Keycloak client ID
- `keycloak_client_secret`: Your Keycloak client secret

### 3. Test Scenarios

#### Health & Monitoring Tests
```bash
# Test all health endpoints
GET /health          # Cached health status
GET /health/detailed # Real-time health check
GET /ready          # Kubernetes readiness
GET /live           # Kubernetes liveness
GET /metrics        # Prometheus metrics
```

#### User Management Tests
```bash
# Complete user lifecycle
POST /api/v1/users           # Create user
GET  /api/v1/users/{id}      # Get user
PUT  /api/v1/users/{id}      # Update user
GET  /api/v1/users           # List users
DELETE /api/v1/users/{id}    # Delete user
```

#### Token Operations Tests
```bash
# Token validation and refresh
POST /api/v1/tokens/introspect  # Validate token
POST /api/v1/tokens/refresh     # Refresh token
```

### 4. Automated Testing

Run the collection with Newman:

```bash
# Install Newman
npm install -g newman

# Run collection
newman run postman/Auth-Service-Collection.json \
  --environment postman/environment.json \
  --reporters cli,html \
  --reporter-html-export test-results.html
```

## 📊 Monitoring & Observability

### 1. Grafana Dashboards

Access: http://localhost:3000 (admin/admin)

**Available Dashboards**:
- **Auth Service - Overview**: High-level service metrics
- **Auth Service - Authentication**: JWT and auth-specific metrics  
- **Auth Service - Keycloak Operations**: Keycloak client performance

### 2. Prometheus Metrics

Access: http://localhost:9090

**Key Metrics to Monitor**:
```promql
# Request Rate
rate(auth_service_http_requests_total[5m])

# Error Rate  
rate(auth_service_http_requests_total{status_code=~"5.."}[5m])

# Response Time
histogram_quantile(0.95, rate(auth_service_http_request_duration_seconds_bucket[5m]))

# Keycloak Performance
rate(auth_service_keycloak_requests_total[5m])
```

### 3. Jaeger Tracing

Access: http://localhost:16686

**Trace Analysis**:
- Search for service: `auth-service`
- Look for operations: `http.*`, `keycloak.*`, `jwt.*`
- Analyze slow requests and errors

### 4. Health Monitoring

```bash
# Quick health check
curl http://localhost:8080/health

# Detailed health with dependencies
curl http://localhost:8080/health/detailed

# Kubernetes probes
curl http://localhost:8080/ready  # Readiness
curl http://localhost:8080/live   # Liveness
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Service Won't Start

```bash
# Check if ports are available
lsof -i :8080  # HTTP port
lsof -i :8081  # gRPC port

# Check Docker services
docker-compose ps
docker-compose logs auth-service
```

#### 2. Keycloak Connection Issues

```bash
# Verify Keycloak is running
curl http://localhost:8090/health

# Check Keycloak logs
docker-compose logs keycloak

# Test admin credentials
curl -X POST http://localhost:8090/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=auth-service&client_secret=YOUR_SECRET"
```

#### 3. Redis Connection Issues

```bash
# Test Redis connectivity
docker-compose exec redis redis-cli ping

# Check Redis logs
docker-compose logs redis

# Verify Redis configuration
docker-compose exec redis redis-cli CONFIG GET "*"
```

#### 4. Metrics Not Appearing

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify service metrics endpoint
curl http://localhost:8080/metrics

# Check OpenTelemetry collector
docker-compose logs otel-collector
```

### Performance Issues

#### High Latency
1. Check Jaeger traces for slow operations
2. Monitor Keycloak response times
3. Verify Redis cache hit ratios
4. Check database connection pools

#### High Error Rates
1. Review Grafana error dashboards
2. Check Prometheus alerting rules
3. Analyze application logs
4. Verify Keycloak configuration

### Log Analysis

```bash
# Application logs
docker-compose logs -f auth-service

# All services logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f keycloak
docker-compose logs -f redis
docker-compose logs -f prometheus
```

## 🔒 Security Considerations

### Production Deployment

1. **Change Default Passwords**:
   - Keycloak admin password
   - Grafana admin password
   - Database passwords

2. **Use HTTPS**:
   - Configure TLS certificates
   - Update all URLs to HTTPS
   - Enable secure cookies

3. **Network Security**:
   - Use Docker networks
   - Restrict port access
   - Configure firewalls

4. **Secrets Management**:
   - Use environment variables
   - Consider HashiCorp Vault
   - Rotate credentials regularly

### Monitoring Security

1. **Enable Authentication** for monitoring tools
2. **Restrict Access** to metrics endpoints
3. **Monitor Security Events** in logs
4. **Set up Alerts** for suspicious activity

## 📈 Performance Tuning

### Application Tuning

```bash
# Go runtime tuning
export GOGC=100
export GOMAXPROCS=4

# Connection pool tuning
export REDIS_MAX_IDLE=10
export REDIS_MAX_ACTIVE=100
```

### Infrastructure Tuning

1. **Redis Configuration**:
   - Increase memory limit
   - Configure persistence
   - Tune connection pools

2. **Keycloak Optimization**:
   - Increase heap size
   - Configure database connection pools
   - Enable caching

3. **Monitoring Stack**:
   - Adjust Prometheus retention
   - Configure Grafana caching
   - Optimize Jaeger sampling

## 🎯 Load Testing

### Using Artillery

```bash
# Install Artillery
npm install -g artillery

# Create load test config
cat > load-test.yml << EOF
config:
  target: 'http://localhost:8080'
  phases:
    - duration: 60
      arrivalRate: 10
scenarios:
  - name: "Health Check Load"
    requests:
      - get:
          url: "/health"
  - name: "User Operations Load"
    requests:
      - get:
          url: "/api/v1/users?page=0&pageSize=10"
EOF

# Run load test
artillery run load-test.yml
```

### Monitoring During Load Tests

1. **Watch Grafana Dashboards** for real-time metrics
2. **Monitor Prometheus Alerts** for threshold breaches
3. **Check Jaeger Traces** for performance degradation
4. **Review Application Logs** for errors

This comprehensive guide should help you successfully deploy, configure, and test the Auth Service with all its monitoring and observability features!