# Production Deployment Guide

This guide covers deploying the Stateless Multi-Realm Auth Service in production environments.

## 🏗️ Architecture Overview

The Auth Service is designed as a **stateless, horizontally scalable API gateway** that integrates with Keycloak for authentication and authorization.

### Key Components
- **Auth Service**: Stateless Go application (multiple instances)
- **Keycloak**: Identity and Access Management server
- **Redis**: Caching layer for performance
- **PostgreSQL**: Database for Keycloak
- **Load Balancer**: Distributes traffic across Auth Service instances

## 🔧 Keycloak Configuration

### Required Client Configuration

For each realm you want to support, create a client with these settings:

```json
{
  "clientId": "your-auth-service-client",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "your-secure-client-secret",
  "serviceAccountsEnabled": true,
  "directAccessGrantsEnabled": true,
  "standardFlowEnabled": true,
  "fullScopeAllowed": true
}
```

### Required Service Account Roles

The client's service account must have these **realm-management** roles:

- `manage-users` - Create, update, delete users
- `manage-clients` - Manage client configurations
- `manage-realm` - Full realm management
- `view-users` - View user information
- `view-clients` - View client information
- `view-realm` - View realm settings
- `create-client` - Create new clients

### Keycloak Admin Setup

1. **Access Keycloak Admin Console**: `https://your-keycloak-domain/admin`
2. **Select Target Realm** or create a new one
3. **Create Client**:
   - Go to `Clients` → `Create`
   - Set `Client ID` and configure as above
4. **Configure Service Account**:
   - Go to `Clients` → `[Your Client]` → `Service Account Roles`
   - Assign `realm-management` roles listed above

## 🚀 Deployment Options

### Option 1: Kubernetes Deployment

#### Auth Service Deployment
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
        image: your-registry/auth-service:latest
        ports:
        - containerPort: 8080
        - containerPort: 8081
        env:
        - name: KEYCLOAK_BASE_URL
          value: "https://your-keycloak-domain"
        - name: KEYCLOAK_REALM
          value: "your-realm"
        - name: KEYCLOAK_CLIENT_ID
          value: "your-client-id"
        - name: KEYCLOAK_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-service-secrets
              key: keycloak-client-secret
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
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

#### Service Configuration
```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
spec:
  selector:
    app: auth-service
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: grpc
    port: 8081
    targetPort: 8081
  type: ClusterIP
```

#### Ingress Configuration
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - auth-api.yourdomain.com
    secretName: auth-service-tls
  rules:
  - host: auth-api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 80
```

### Option 2: Docker Compose (Production)

```yaml
version: '3.8'

services:
  auth-service:
    image: your-registry/auth-service:latest
    deploy:
      replicas: 3
    environment:
      - KEYCLOAK_BASE_URL=https://your-keycloak-domain
      - KEYCLOAK_REALM=your-realm
      - KEYCLOAK_CLIENT_ID=your-client-id
      - KEYCLOAK_CLIENT_SECRET=your-secure-secret
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis
      - keycloak
    networks:
      - auth-network

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - auth-service
    networks:
      - auth-network

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - auth-network

networks:
  auth-network:
    driver: bridge

volumes:
  redis_data:
```

## 🔒 Security Considerations

### Environment Variables
Never hardcode secrets. Use secure secret management:

```bash
# Kubernetes Secrets
kubectl create secret generic auth-service-secrets \
  --from-literal=keycloak-client-secret=your-secure-secret

# Docker Secrets
echo "your-secure-secret" | docker secret create keycloak_client_secret -
```

### Network Security
- Use HTTPS/TLS for all external communication
- Implement network policies in Kubernetes
- Use private networks for internal communication
- Enable Keycloak security headers

### Rate Limiting
Implement rate limiting at the load balancer level:

```nginx
# Nginx rate limiting
http {
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
    
    server {
        location /api/v1/auth/ {
            limit_req zone=auth burst=20 nodelay;
            proxy_pass http://auth-service;
        }
    }
}
```

## 📊 Monitoring & Observability

### Health Checks
The service provides multiple health check endpoints:

- `/health` - Basic health status
- `/health/detailed` - Detailed dependency health
- `/ready` - Readiness probe
- `/live` - Liveness probe

### Metrics
Prometheus metrics available at `/metrics`:

```yaml
# Prometheus scrape config
scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:8080']
    metrics_path: /metrics
    scrape_interval: 15s
```

### Logging
Configure structured logging:

```yaml
environment:
  - LOG_LEVEL=info
  - LOG_FORMAT=json
```

## 🔄 Multi-Realm Configuration

### Environment Variables per Realm
For multi-tenant deployments, you can deploy separate instances per realm:

```yaml
# Tenant A
- KEYCLOAK_REALM=tenant-a
- KEYCLOAK_CLIENT_ID=tenant-a-client
- KEYCLOAK_CLIENT_SECRET=tenant-a-secret

# Tenant B  
- KEYCLOAK_REALM=tenant-b
- KEYCLOAK_CLIENT_ID=tenant-b-client
- KEYCLOAK_CLIENT_SECRET=tenant-b-secret
```

### Dynamic Multi-Realm
For true multi-realm support, clients specify realm in headers:

```bash
curl -X POST https://auth-api.yourdomain.com/api/v1/auth/login \
  -H "X-Realm-Name: tenant-a" \
  -H "X-Client-Id: tenant-a-client" \
  -H "X-Client-Secret: tenant-a-secret" \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'
```

## 🚦 Load Balancing

### Nginx Configuration
```nginx
upstream auth_service {
    least_conn;
    server auth-service-1:8080 max_fails=3 fail_timeout=30s;
    server auth-service-2:8080 max_fails=3 fail_timeout=30s;
    server auth-service-3:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name auth-api.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location / {
        proxy_pass http://auth_service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📈 Scaling Guidelines

### Horizontal Scaling
- **Stateless Design**: Scale instances based on CPU/memory usage
- **No Session State**: Each request is independent
- **Database Connections**: Monitor Keycloak database connections

### Performance Tuning
```yaml
# Resource recommendations per instance
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi" 
    cpu: "500m"

# For high-traffic environments
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

## 🔧 Troubleshooting

### Common Issues

#### 403 Forbidden Errors
- **Cause**: Missing service account roles
- **Solution**: Assign proper realm-management roles to client

#### Realm Not Found
- **Cause**: Incorrect realm name in headers
- **Solution**: Verify realm exists and header values

#### Connection Timeouts
- **Cause**: Network issues or Keycloak overload
- **Solution**: Check network connectivity and Keycloak performance

### Debug Commands
```bash
# Check service health
curl https://auth-api.yourdomain.com/health/detailed

# Test authentication
curl -X POST https://auth-api.yourdomain.com/api/v1/auth/login \
  -H "X-Realm-Name: your-realm" \
  -H "X-Client-Id: your-client" \
  -H "X-Client-Secret: your-secret" \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test"}'

# Check Keycloak connectivity
curl https://your-keycloak-domain/realms/your-realm
```

## 📋 Production Checklist

- [ ] Keycloak client configured with service account roles
- [ ] Secrets managed securely (not hardcoded)
- [ ] HTTPS/TLS enabled for all external communication
- [ ] Health checks configured
- [ ] Monitoring and alerting set up
- [ ] Rate limiting implemented
- [ ] Load balancer configured
- [ ] Backup strategy for Redis and Keycloak data
- [ ] Log aggregation configured
- [ ] Security headers enabled
- [ ] Network policies applied (Kubernetes)

## 🆘 Support

For production issues:
1. Check service logs and health endpoints
2. Verify Keycloak connectivity and client configuration
3. Monitor resource usage and scaling metrics
4. Review network connectivity between services

The Auth Service is designed for high availability and horizontal scaling in production environments.