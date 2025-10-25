#!/bin/bash

# Auth Service - Complete Stack Test Script
# This script validates that all services are running correctly

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVICE_URL="http://localhost:8080"
KEYCLOAK_URL="http://localhost:8090"
PROMETHEUS_URL="http://localhost:9090"
GRAFANA_URL="http://localhost:3000"
JAEGER_URL="http://localhost:16686"
REDIS_HOST="localhost"
REDIS_PORT="6379"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++))
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Test functions
test_service_health() {
    local service_name=$1
    local url=$2
    local expected_status=${3:-200}
    
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "$expected_status"; then
        print_success "$service_name is healthy"
        return 0
    else
        print_error "$service_name is not responding correctly"
        return 1
    fi
}

test_redis_connection() {
    if command -v redis-cli >/dev/null 2>&1; then
        if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping | grep -q "PONG"; then
            print_success "Redis connection successful"
            return 0
        else
            print_error "Redis connection failed"
            return 1
        fi
    else
        print_warning "redis-cli not found, skipping Redis test"
        return 0
    fi
}

test_auth_service_endpoints() {
    local base_url=$1
    
    # Test health endpoints
    test_service_health "Auth Service Health" "$base_url/health"
    test_service_health "Auth Service Detailed Health" "$base_url/health/detailed"
    test_service_health "Auth Service Readiness" "$base_url/ready"
    test_service_health "Auth Service Liveness" "$base_url/live"
    test_service_health "Auth Service Metrics" "$base_url/metrics"
    
    # Test API endpoints (these might return errors but should respond)
    if curl -s -o /dev/null -w "%{http_code}" "$base_url/api/v1/users" | grep -qE "^[2-5][0-9][0-9]$"; then
        print_success "Auth Service API endpoints responding"
    else
        print_error "Auth Service API endpoints not responding"
    fi
}

test_keycloak_admin() {
    local keycloak_url=$1
    
    # Test Keycloak admin console
    if curl -s "$keycloak_url/realms/master" | grep -q "master"; then
        print_success "Keycloak master realm accessible"
    else
        print_error "Keycloak master realm not accessible"
    fi
    
    # Test Keycloak health
    test_service_health "Keycloak Health" "$keycloak_url/health"
}

test_monitoring_stack() {
    # Test Prometheus
    test_service_health "Prometheus" "$PROMETHEUS_URL/-/healthy"
    
    # Test Grafana
    test_service_health "Grafana" "$GRAFANA_URL/api/health"
    
    # Test Jaeger
    test_service_health "Jaeger" "$JAEGER_URL"
    
    # Test if Prometheus is scraping Auth Service
    if curl -s "$PROMETHEUS_URL/api/v1/targets" | grep -q "auth-service"; then
        print_success "Prometheus is scraping Auth Service"
    else
        print_error "Prometheus is not scraping Auth Service"
    fi
}

test_docker_services() {
    print_header "Docker Services Status"
    
    if command -v docker-compose >/dev/null 2>&1; then
        # Check if docker-compose.yml exists
        if [ -f "docker-compose.yml" ]; then
            # Get service status
            local services=$(docker-compose ps --services)
            for service in $services; do
                local status=$(docker-compose ps -q "$service" | xargs docker inspect -f '{{.State.Status}}' 2>/dev/null || echo "not found")
                if [ "$status" = "running" ]; then
                    print_success "Docker service '$service' is running"
                else
                    print_error "Docker service '$service' is not running (status: $status)"
                fi
            done
        else
            print_warning "docker-compose.yml not found in current directory"
        fi
    else
        print_warning "docker-compose not found, skipping Docker services test"
    fi
}

test_auth_service_functionality() {
    print_header "Auth Service Functionality Tests"
    
    local base_url=$1
    
    # Test user creation (this will likely fail without proper Keycloak setup, but should return a proper error)
    local create_response=$(curl -s -w "%{http_code}" -X POST "$base_url/api/v1/users" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","email":"test@example.com","enabled":true}' \
        -o /tmp/create_user_response.json)
    
    if echo "$create_response" | grep -qE "^[2-5][0-9][0-9]$"; then
        print_success "User creation endpoint responding (status: $create_response)"
    else
        print_error "User creation endpoint not responding properly"
    fi
    
    # Test token introspection
    local introspect_response=$(curl -s -w "%{http_code}" -X POST "$base_url/api/v1/tokens/introspect" \
        -H "Content-Type: application/json" \
        -d '{"token":"invalid.test.token"}' \
        -o /tmp/introspect_response.json)
    
    if echo "$introspect_response" | grep -qE "^[2-5][0-9][0-9]$"; then
        print_success "Token introspection endpoint responding (status: $introspect_response)"
    else
        print_error "Token introspection endpoint not responding properly"
    fi
}

test_metrics_collection() {
    print_header "Metrics Collection Tests"
    
    # Check if Auth Service metrics are available
    local metrics_response=$(curl -s "$AUTH_SERVICE_URL/metrics")
    
    if echo "$metrics_response" | grep -q "auth_service_http_requests_total"; then
        print_success "Auth Service custom metrics are being collected"
    else
        print_error "Auth Service custom metrics not found"
    fi
    
    if echo "$metrics_response" | grep -q "go_memstats"; then
        print_success "Go runtime metrics are being collected"
    else
        print_error "Go runtime metrics not found"
    fi
    
    # Check if Prometheus can query Auth Service metrics
    local prom_query_response=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=up{job=\"auth-service\"}")
    
    if echo "$prom_query_response" | grep -q "auth-service"; then
        print_success "Prometheus can query Auth Service metrics"
    else
        print_error "Prometheus cannot query Auth Service metrics"
    fi
}

run_performance_test() {
    print_header "Basic Performance Tests"
    
    # Simple load test on health endpoint
    print_info "Running 10 concurrent requests to health endpoint..."
    
    local start_time=$(date +%s.%N)
    for i in {1..10}; do
        curl -s "$AUTH_SERVICE_URL/health" > /dev/null &
    done
    wait
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l)
    
    print_info "10 concurrent health checks completed in ${duration}s"
    
    if (( $(echo "$duration < 2.0" | bc -l) )); then
        print_success "Health endpoint performance is acceptable"
    else
        print_warning "Health endpoint performance might be slow"
    fi
}

cleanup_temp_files() {
    rm -f /tmp/create_user_response.json /tmp/introspect_response.json
}

# Main execution
main() {
    print_header "Auth Service Stack Validation"
    print_info "Testing complete Auth Service stack..."
    
    # Test Docker services first
    test_docker_services
    
    # Wait a moment for services to be ready
    print_info "Waiting 5 seconds for services to be ready..."
    sleep 5
    
    # Test individual services
    print_header "Service Health Checks"
    test_service_health "Auth Service" "$AUTH_SERVICE_URL/health"
    test_service_health "Keycloak" "$KEYCLOAK_URL/health"
    test_redis_connection
    
    # Test Auth Service endpoints
    print_header "Auth Service Endpoints"
    test_auth_service_endpoints "$AUTH_SERVICE_URL"
    
    # Test Keycloak
    print_header "Keycloak Tests"
    test_keycloak_admin "$KEYCLOAK_URL"
    
    # Test monitoring stack
    print_header "Monitoring Stack"
    test_monitoring_stack
    
    # Test Auth Service functionality
    test_auth_service_functionality "$AUTH_SERVICE_URL"
    
    # Test metrics collection
    test_metrics_collection
    
    # Run basic performance test
    run_performance_test
    
    # Cleanup
    cleanup_temp_files
    
    # Summary
    print_header "Test Summary"
    local total_tests=$((TESTS_PASSED + TESTS_FAILED))
    print_info "Total tests: $total_tests"
    print_success "Passed: $TESTS_PASSED"
    
    if [ $TESTS_FAILED -gt 0 ]; then
        print_error "Failed: $TESTS_FAILED"
        print_error "Some tests failed. Please check the output above for details."
        exit 1
    else
        print_success "All tests passed! 🎉"
        print_info "Your Auth Service stack is running correctly."
        
        echo -e "\n${BLUE}Quick Access URLs:${NC}"
        echo -e "• Auth Service: $AUTH_SERVICE_URL"
        echo -e "• Keycloak Admin: $KEYCLOAK_URL"
        echo -e "• Grafana: $GRAFANA_URL (admin/admin)"
        echo -e "• Prometheus: $PROMETHEUS_URL"
        echo -e "• Jaeger: $JAEGER_URL"
        
        exit 0
    fi
}

# Check if bc is available for performance calculations
if ! command -v bc >/dev/null 2>&1; then
    print_warning "bc (calculator) not found. Performance timing will be skipped."
fi

# Run main function
main "$@"