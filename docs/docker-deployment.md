# Docker Deployment Guide

This guide covers deploying the Auth Service using Docker and Docker Compose.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Git (for cloning the repository)

## Quick Start

### Development Deployment

```bash
# Clone the repository
git clone <repository-url>
cd auth-service-go

# Build and start development environment
make deploy-dev

# Or manually:
make docker-build
make docker-up
```

### Production Deployment

```bash
# Build production image with version tag
make docker-build-prod

# Configure production environment
cp .env.prod.example .env.prod
# Edit .env.prod with your production values

# Start production environment
make deploy-prod

# Or manually:
docker-compose -f docker-compose.prod.yml up -d
```

## Docker Images

### Multi-stage Build

The Dockerfile uses a multi-stage build process:

1. **Builder Stage**: 
   - Uses `golang:1.21-alpine`
   - Installs `buf` for protobuf generation
   - Downloads Go dependencies
   - Generates protobuf files
   - Builds the application binary

2. **Runtime Stage**:
   - Uses minimal `alpine:3.18` image
   - Runs as non-root user for security
   - Includes health checks
   - Optimized for production

### Image Size

- Builder image: ~1.2GB (temporary)
- Final runtime image: ~20MB
- Includes only necessary runtime dependencies

## Available Make Commands

### Docker Build Commands

```bash
make docker-build          # Build development image
make docker-build-prod     # Build production image with git hash tag
make docker-run           # Run container locally
make docker-clean         # Clean Docker images and containers
```

### Development Environment

```bash
make docker-up            # Start development environment
make docker-down          # Stop development environment
make docker-logs          # Show logs from development environment
make deploy-dev           # Build and deploy development environment
```

### Production Environment

```bash
make docker-up-prod       # Start production environment
make docker-down-prod     # Stop production environment
make docker-logs-prod     # Show logs from production environment
make deploy-prod          # Build and deploy production environment
```

### Local Development (without Docker)

```bash
make build-local-with-tools  # Install tools and build locally
make build-local            # Build locally (requires Go and buf)
```

## Environment Configuration

### Development (.env)

The development environment uses default values suitable for local development.

### Production (.env.prod)

Copy `.env.prod.example` to `.env.prod` and configure:

```bash
# Required production variables
KEYCLOAK_CLIENT_SECRET=your-secure-client-secret
KEYCLOAK_ADMIN_PASSWORD=your-secure-admin-password
POSTGRES_PASSWORD=your-secure-db-password
KC_DB_PASSWORD=your-secure-db-password

# Optional customizations
SERVICE_VERSION=v1.0.0
LOG_LEVEL=warn
KEYCLOAK_BASE_URL=https://your-keycloak-domain.com
```

## Service Architecture

### Development Stack

- **auth-service**: Main application (ports 8080, 8081)
- **redis**: Caching layer (port 6379)
- **keycloak**: Authentication server (port 8090)
- **postgres**: Database for Keycloak (internal)
- **otel-collector**: Telemetry collection (ports 4317, 4318)
- **jaeger**: Distributed tracing UI (port 16686)
- **prometheus**: Metrics collection (port 9090)
- **grafana**: Monitoring dashboards (port 3000)

### Production Stack

Simplified stack for production:
- **auth-service**: Main application
- **redis**: Caching layer
- **keycloak**: Authentication server
- **postgres**: Database for Keycloak

## Health Checks

All services include health checks:

```bash
# Check auth service health
curl http://localhost:8080/health

# Check all services status
docker-compose ps
```

## Resource Limits (Production)

### Auth Service
- CPU: 1.0 limit, 0.5 reservation
- Memory: 512MB limit, 256MB reservation

### Redis
- CPU: 0.5 limit, 0.25 reservation
- Memory: 256MB limit, 128MB reservation

### Keycloak
- CPU: 1.0 limit, 0.5 reservation
- Memory: 1GB limit, 512MB reservation

### PostgreSQL
- CPU: 1.0 limit, 0.5 reservation
- Memory: 1GB limit, 512MB reservation

## Security Considerations

### Container Security

1. **Non-root user**: Application runs as `appuser` (UID 1001)
2. **Minimal base image**: Alpine Linux for reduced attack surface
3. **Static binary**: No dynamic dependencies
4. **Read-only filesystem**: Consider adding `--read-only` flag

### Network Security

1. **Internal network**: Services communicate via Docker network
2. **Port exposure**: Only necessary ports exposed to host
3. **Environment variables**: Sensitive data via environment variables

### Production Hardening

```bash
# Run with additional security options
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -p 8080:8080 \
  auth-service-go:latest
```

## Monitoring and Logging

### Logs

```bash
# View auth service logs
docker-compose logs -f auth-service

# View all logs
docker-compose logs -f

# Production logs with rotation
# Configured in docker-compose.prod.yml
```

### Metrics

- Prometheus metrics: http://localhost:9090
- Grafana dashboards: http://localhost:3000 (admin/admin)
- Application metrics: http://localhost:8080/metrics

### Tracing

- Jaeger UI: http://localhost:16686
- OpenTelemetry endpoint: http://localhost:4317

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 8080, 8081, 6379, 8090 are available
2. **Memory issues**: Increase Docker memory allocation
3. **Build failures**: Check Docker daemon and network connectivity

### Debug Commands

```bash
# Check container status
docker-compose ps

# View container logs
docker-compose logs auth-service

# Execute shell in container
docker-compose exec auth-service sh

# Check resource usage
docker stats

# Inspect container
docker inspect auth-service
```

### Performance Tuning

1. **Increase memory limits** for high-load scenarios
2. **Adjust Redis maxmemory** based on cache requirements
3. **Configure PostgreSQL** connection pooling
4. **Enable Keycloak clustering** for high availability

## Backup and Recovery

### Database Backup

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U keycloak keycloak > backup.sql

# Restore PostgreSQL
docker-compose exec -T postgres psql -U keycloak keycloak < backup.sql
```

### Redis Backup

```bash
# Backup Redis
docker-compose exec redis redis-cli BGSAVE
docker cp redis:/data/dump.rdb ./redis-backup.rdb
```

## Scaling

### Horizontal Scaling

```bash
# Scale auth service instances
docker-compose up -d --scale auth-service=3

# Use load balancer (nginx, traefik, etc.)
```

### Vertical Scaling

Update resource limits in `docker-compose.prod.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 1G
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Build Docker image
  run: make docker-build-prod

- name: Deploy to production
  run: make deploy-prod
```

### GitLab CI Example

```yaml
build:
  script:
    - make docker-build-prod
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

## Support

For issues and questions:
1. Check container logs: `docker-compose logs`
2. Verify health checks: `docker-compose ps`
3. Review resource usage: `docker stats`
4. Consult application metrics and traces