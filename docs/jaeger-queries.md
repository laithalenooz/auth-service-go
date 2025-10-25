# Jaeger APM Dashboard Queries

This document provides example queries and analysis techniques for monitoring the Auth Service using Jaeger/Tempo for distributed tracing.

## Overview

The Auth Service is instrumented with OpenTelemetry tracing to provide comprehensive observability across all operations. This includes:

- HTTP request tracing
- gRPC operation tracing  
- Keycloak client operation tracing
- JWT validation tracing
- Cache operation tracing

## High-Latency Keycloak Operations

### 1. Finding Slow Keycloak Calls

**Query**: Find traces where Keycloak operations take longer than 1 second
```
service="auth-service" AND operation="keycloak.*" AND duration>1s
```

**Analysis Points**:
- Look for `keycloak.user.create`, `keycloak.user.get`, `keycloak.token.introspect` operations
- Check for network latency vs processing time
- Identify if admin token refresh is causing delays

### 2. Keycloak Admin Token Issues

**Query**: Find traces with admin token refresh problems
```
service="auth-service" AND operation="keycloak.admin.token" AND (error=true OR duration>500ms)
```

**What to Look For**:
- Frequent token refresh attempts
- Authentication failures
- Network timeouts to Keycloak

### 3. User Creation Performance

**Query**: Analyze user creation latency patterns
```
service="auth-service" AND operation="keycloak.user.create" AND duration>200ms
```

**Performance Indicators**:
- Time spent in JSON marshaling
- HTTP request duration to Keycloak
- Response parsing time

## JWT Validation Performance

### 4. JWT Validation Bottlenecks

**Query**: Find slow JWT validation operations
```
service="auth-service" AND operation="jwt.validation" AND duration>100ms
```

**Common Issues**:
- JWKS key retrieval delays
- Public key parsing problems
- Token signature verification time

### 5. JWKS Cache Performance

**Query**: Analyze JWKS cache hit/miss patterns
```
service="auth-service" AND operation="jwks.fetch" 
```

**Optimization Opportunities**:
- Cache miss frequency
- Key retrieval latency from Keycloak
- Redis cache performance

## HTTP Request Analysis

### 6. Slow API Endpoints

**Query**: Find HTTP requests with high latency
```
service="auth-service" AND operation="http.*" AND duration>500ms
```

**Breakdown Analysis**:
- Authentication middleware time
- Business logic processing time
- Database/cache operation time
- Response serialization time

### 7. Authentication Failures

**Query**: Trace authentication failure patterns
```
service="auth-service" AND (http.status_code=401 OR http.status_code=403)
```

**Investigation Points**:
- JWT validation failure reasons
- Token expiration patterns
- Invalid signature issues

## Cache Performance Analysis

### 8. Redis Cache Operations

**Query**: Analyze cache operation performance
```
service="auth-service" AND operation="cache.*" AND duration>50ms
```

**Performance Metrics**:
- Cache hit/miss ratios
- Network latency to Redis
- Serialization/deserialization time

### 9. Cache Miss Impact

**Query**: Find operations affected by cache misses
```
service="auth-service" AND tags.cache_result="miss"
```

**Impact Analysis**:
- Downstream Keycloak calls triggered by cache misses
- Performance degradation patterns
- Cache warming opportunities

## Error Analysis

### 10. Service Error Patterns

**Query**: Find all error traces in the service
```
service="auth-service" AND error=true
```

**Error Categories**:
- Network errors (Keycloak, Redis connectivity)
- Authentication errors (JWT validation, token expiry)
- Business logic errors (user not found, invalid requests)

### 11. Timeout Analysis

**Query**: Find operations that timeout
```
service="auth-service" AND (tags.error_type="timeout" OR duration>10s)
```

**Timeout Sources**:
- Keycloak API timeouts
- Redis connection timeouts
- HTTP client timeouts

## Performance Optimization Queries

### 12. Top Slowest Operations

**Query**: Find the slowest operations across all services
```
service="auth-service" ORDER BY duration DESC LIMIT 100
```

**Optimization Targets**:
- Identify bottleneck operations
- Find optimization opportunities
- Track performance improvements over time

### 13. Concurrent Request Analysis

**Query**: Analyze concurrent request patterns
```
service="auth-service" AND operation="http.*" GROUP BY time(1m)
```

**Concurrency Insights**:
- Peak load patterns
- Resource contention issues
- Scaling requirements

## Custom Dashboard Queries

### 14. Service Health Overview

**Query**: Overall service health metrics
```
service="auth-service" AND operation IN ["http.*", "grpc.*"] 
```

**Health Indicators**:
- Request success rates
- Average response times
- Error frequency patterns

### 15. Dependency Health

**Query**: Monitor external dependency health
```
service="auth-service" AND operation IN ["keycloak.*", "cache.*"]
```

**Dependency Metrics**:
- Keycloak availability and performance
- Redis cache performance
- Network connectivity issues

## Alerting Queries

### 16. High Error Rate Alert

**Query**: Detect when error rate exceeds threshold
```
service="auth-service" AND error=true AND time>now()-5m
```

**Alert Conditions**:
- Error rate > 5% over 5 minutes
- Consecutive failures > 10
- Critical operation failures

### 17. High Latency Alert

**Query**: Detect performance degradation
```
service="auth-service" AND duration>1s AND time>now()-5m
```

**Performance Thresholds**:
- P95 latency > 1 second
- P99 latency > 2 seconds
- Average latency > 500ms

## Usage Tips

### Trace Correlation
- Use trace IDs to follow requests across service boundaries
- Correlate HTTP requests with underlying gRPC calls
- Track user sessions across multiple operations

### Performance Baselines
- Establish baseline performance metrics
- Monitor performance trends over time
- Set up automated performance regression detection

### Debugging Workflows
1. Start with high-level service metrics
2. Drill down to specific operations
3. Analyze trace details for root cause
4. Correlate with logs and metrics

### Best Practices
- Use time-based filtering for recent issues
- Combine multiple query conditions for precise analysis
- Export traces for detailed offline analysis
- Set up saved queries for common investigations

## Integration with Metrics

Combine Jaeger traces with Prometheus metrics for comprehensive analysis:

- Use trace IDs to correlate with metric timestamps
- Validate trace insights with metric aggregations
- Cross-reference performance patterns between systems

This combination provides both detailed request-level insights (traces) and statistical trends (metrics) for complete observability.