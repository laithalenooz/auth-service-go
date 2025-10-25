# Auth Service Alerting Guide

This document provides comprehensive information about the Prometheus alerting rules configured for the Auth Service, including alert descriptions, thresholds, and recommended actions.

## Overview

The Auth Service has 25+ alerting rules organized into 4 main categories:
- **Service Health & Performance**: Core service availability and performance
- **Business Logic**: Authentication and user operation failures
- **Dependencies**: External service health (Keycloak, Redis)
- **SLA Monitoring**: Service level agreement compliance

## Alert Categories

### 1. Service Health & Performance Alerts

#### AuthServiceHighErrorRate
- **Threshold**: >5% error rate (5xx responses) for 2+ minutes
- **Severity**: Critical
- **Description**: High rate of server errors indicating service issues
- **Actions**:
  - Check service logs for error patterns
  - Verify database/cache connectivity
  - Review recent deployments
  - Scale service if needed

#### AuthServiceHighLatency / AuthServiceVeryHighLatency
- **Thresholds**: >1s (warning) / >2s (critical) 95th percentile latency
- **Duration**: 3min (warning) / 1min (critical)
- **Description**: Service response times are degraded
- **Actions**:
  - Check Keycloak response times
  - Review cache hit ratios
  - Analyze slow queries in traces
  - Consider horizontal scaling

#### AuthServiceDown
- **Threshold**: Service unavailable for 1+ minute
- **Severity**: Critical
- **Description**: Service is completely unavailable
- **Actions**:
  - Check service health endpoints
  - Verify container/pod status
  - Review infrastructure issues
  - Initiate incident response

### 2. Authentication & JWT Alerts

#### JWTValidationFailureRate
- **Threshold**: >15% JWT validation failures for 3+ minutes
- **Severity**: Warning
- **Description**: High rate of invalid tokens
- **Actions**:
  - Check token expiration patterns
  - Verify JWKS key rotation
  - Review client token generation
  - Check for clock skew issues

#### JWTValidationHighLatency
- **Threshold**: >500ms 95th percentile JWT validation time
- **Duration**: 5+ minutes
- **Description**: JWT validation is slow
- **Actions**:
  - Check JWKS cache performance
  - Verify Keycloak connectivity
  - Review public key retrieval times
  - Consider JWKS caching improvements

#### HighAuthenticationFailureRate
- **Threshold**: >1 failure/second for 3+ minutes
- **Severity**: Warning
- **Description**: Elevated authentication failures
- **Actions**:
  - Review authentication logs
  - Check for brute force attempts
  - Verify user credential issues
  - Consider rate limiting

#### SuspiciousAuthenticationActivity
- **Threshold**: >5 failures/second for 30+ seconds
- **Severity**: Critical
- **Description**: Potential security attack
- **Actions**:
  - **IMMEDIATE**: Review security logs
  - Check source IP patterns
  - Consider blocking suspicious IPs
  - Escalate to security team
  - Review rate limiting policies

### 3. Keycloak Integration Alerts

#### KeycloakHighErrorRate
- **Threshold**: >10% Keycloak operation errors for 2+ minutes
- **Severity**: Critical
- **Description**: High failure rate for Keycloak operations
- **Actions**:
  - Check Keycloak service health
  - Verify network connectivity
  - Review admin token validity
  - Check Keycloak resource limits

#### KeycloakHighLatency
- **Threshold**: >2s 95th percentile Keycloak response time
- **Duration**: 3+ minutes
- **Description**: Keycloak operations are slow
- **Actions**:
  - Check Keycloak performance metrics
  - Review database performance
  - Verify network latency
  - Consider Keycloak scaling

#### KeycloakAdminTokenRefreshFailure
- **Threshold**: >0.1 failures/second for 1+ minute
- **Severity**: Critical
- **Description**: Cannot refresh admin tokens
- **Actions**:
  - Verify admin credentials
  - Check Keycloak admin API availability
  - Review token endpoint configuration
  - Restart service if needed

### 4. Cache Performance Alerts

#### CacheLowHitRatio
- **Threshold**: <80% hit ratio for 10+ minutes
- **Severity**: Warning
- **Description**: Cache efficiency is degraded
- **Actions**:
  - Review cache key patterns
  - Check cache expiration policies
  - Verify Redis connectivity
  - Consider cache warming strategies

#### CacheHighLatency
- **Threshold**: >100ms 95th percentile cache operation time
- **Duration**: 5+ minutes
- **Description**: Cache operations are slow
- **Actions**:
  - Check Redis performance
  - Review network latency to Redis
  - Verify Redis resource utilization
  - Consider Redis scaling

### 5. Resource Usage Alerts

#### HighGoroutineCount
- **Threshold**: >1000 goroutines for 5+ minutes
- **Severity**: Warning
- **Description**: Potential goroutine leak
- **Actions**:
  - Review goroutine profiles
  - Check for blocked operations
  - Look for connection leaks
  - Consider service restart

#### HighMemoryUsage
- **Threshold**: >500MB heap memory for 5+ minutes
- **Severity**: Warning
- **Description**: High memory consumption
- **Actions**:
  - Review memory profiles
  - Check for memory leaks
  - Verify cache sizes
  - Consider memory limits

### 6. SLA Compliance Alerts

#### AuthServiceSLABreach
- **Threshold**: <99.5% availability for 5+ minutes
- **Severity**: Critical
- **Description**: Service availability SLA breach
- **Actions**:
  - **IMMEDIATE**: Escalate to on-call
  - Review all error sources
  - Check infrastructure health
  - Implement immediate fixes
  - Document incident

#### AuthServiceLatencySLABreach
- **Threshold**: >3s 99th percentile latency for 2+ minutes
- **Severity**: Critical
- **Description**: Service latency SLA breach
- **Actions**:
  - **IMMEDIATE**: Investigate performance
  - Check all dependencies
  - Review recent changes
  - Consider emergency scaling
  - Document incident

## Alert Response Procedures

### Severity Levels

#### Critical Alerts
- **Response Time**: Immediate (< 5 minutes)
- **Actions**: Page on-call engineer, start incident response
- **Escalation**: Escalate to senior engineer if not resolved in 15 minutes

#### Warning Alerts
- **Response Time**: Within 30 minutes during business hours
- **Actions**: Investigate and document findings
- **Escalation**: Escalate if pattern continues or worsens

### Investigation Workflow

1. **Acknowledge Alert**
   - Acknowledge in alerting system
   - Check alert context and duration

2. **Initial Assessment**
   - Check service health dashboard
   - Review recent deployments
   - Verify infrastructure status

3. **Deep Investigation**
   - Analyze Grafana dashboards
   - Review Jaeger traces for slow operations
   - Check application logs
   - Examine metrics trends

4. **Resolution**
   - Apply immediate fixes
   - Monitor for improvement
   - Document root cause
   - Update runbooks if needed

## Alert Configuration

### Customizing Thresholds

Alert thresholds can be adjusted in `/docker/prometheus/alert-rules.yml`:

```yaml
# Example: Adjust error rate threshold
- alert: AuthServiceHighErrorRate
  expr: |
    (rate(auth_service_http_requests_total{status_code=~"5.."}[5m]) /
     rate(auth_service_http_requests_total[5m])) * 100 > 3  # Changed from 5 to 3
```

### Adding New Alerts

1. Add rule to appropriate group in `alert-rules.yml`
2. Test with `promtool check rules alert-rules.yml`
3. Reload Prometheus configuration
4. Update this documentation

### Alert Routing (Optional)

To route alerts to different channels, configure Alertmanager:

```yaml
# docker-compose.yml
alertmanager:
  image: prom/alertmanager:latest
  ports:
    - "9093:9093"
  volumes:
    - ./docker/alertmanager:/etc/alertmanager
```

## Monitoring Best Practices

### Alert Fatigue Prevention
- Set appropriate thresholds to avoid false positives
- Use different severity levels appropriately
- Group related alerts together
- Implement alert suppression during maintenance

### Regular Review
- Review alert effectiveness monthly
- Adjust thresholds based on service behavior
- Remove or modify noisy alerts
- Add new alerts for discovered issues

### Documentation
- Keep runbooks updated
- Document common resolution steps
- Share knowledge across team
- Update contact information

## Integration with External Systems

### Slack Integration
```yaml
# alertmanager.yml
route:
  receiver: 'slack-notifications'
receivers:
- name: 'slack-notifications'
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    channel: '#alerts'
    title: 'Auth Service Alert'
```

### PagerDuty Integration
```yaml
# alertmanager.yml
receivers:
- name: 'pagerduty-critical'
  pagerduty_configs:
  - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
    severity: 'critical'
```

## Troubleshooting Alerts

### Common Issues

1. **Alerts Not Firing**
   - Check Prometheus rule evaluation
   - Verify metric names and labels
   - Confirm data is being scraped

2. **False Positives**
   - Review threshold appropriateness
   - Check for data spikes or anomalies
   - Consider using rate() vs increase()

3. **Missing Alerts**
   - Verify Prometheus configuration reload
   - Check rule syntax with promtool
   - Confirm metric availability

### Useful Commands

```bash
# Check rule syntax
promtool check rules alert-rules.yml

# Query alert status
curl http://localhost:9090/api/v1/alerts

# Reload Prometheus config
curl -X POST http://localhost:9090/-/reload
```

This alerting system provides comprehensive coverage of the Auth Service's critical metrics and helps ensure high availability and performance.