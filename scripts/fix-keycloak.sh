#!/bin/bash

# Keycloak Troubleshooting and Fix Script
# This script helps diagnose and fix common Keycloak startup issues

set -e

echo "🔧 Keycloak Troubleshooting Script"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    print_status "Checking Docker status..."
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    print_status "Docker is running ✓"
}

# Clean up existing containers and volumes
cleanup() {
    print_status "Cleaning up existing containers and volumes..."
    
    # Stop and remove containers
    docker-compose down -v 2>/dev/null || true
    
    # Remove specific containers if they exist
    docker rm -f keycloak postgres redis auth-service 2>/dev/null || true
    
    # Remove volumes to avoid import conflicts
    docker volume rm auth-service-go_postgres-data 2>/dev/null || true
    docker volume rm auth-service-go_keycloak-data 2>/dev/null || true
    
    print_status "Cleanup completed ✓"
}

# Check system resources
check_resources() {
    print_status "Checking system resources..."
    
    # Check available memory
    available_mem=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$available_mem" -lt 2048 ]; then
        print_warning "Available memory is ${available_mem}MB. Keycloak requires at least 2GB for optimal performance."
    else
        print_status "Memory check passed: ${available_mem}MB available ✓"
    fi
    
    # Check disk space
    available_disk=$(df -h . | awk 'NR==2{print $4}' | sed 's/G//')
    if [ "${available_disk%.*}" -lt 5 ]; then
        print_warning "Available disk space is ${available_disk}. Consider freeing up space."
    else
        print_status "Disk space check passed: ${available_disk} available ✓"
    fi
}

# Fix file permissions
fix_permissions() {
    print_status "Fixing file permissions..."
    
    # Ensure realm export file exists and is readable
    if [ ! -f "./docker/keycloak/realm-export.json" ]; then
        print_error "Realm export file not found: ./docker/keycloak/realm-export.json"
        exit 1
    fi
    
    chmod 644 ./docker/keycloak/realm-export.json
    print_status "File permissions fixed ✓"
}

# Wait for service to be ready
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    print_status "Waiting for $service to be ready on port $port..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T $service sh -c "nc -z localhost $port" 2>/dev/null; then
            print_status "$service is ready ✓"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "$service failed to start within expected time"
    return 1
}

# Start services in order
start_services() {
    print_status "Starting services in correct order..."
    
    # Start PostgreSQL first
    print_status "Starting PostgreSQL..."
    docker-compose up -d postgres
    
    # Wait for PostgreSQL to be ready
    sleep 10
    
    # Check PostgreSQL health
    print_status "Checking PostgreSQL health..."
    for i in {1..30}; do
        if docker-compose exec -T postgres pg_isready -U keycloak -d keycloak >/dev/null 2>&1; then
            print_status "PostgreSQL is ready ✓"
            break
        fi
        echo -n "."
        sleep 2
        if [ $i -eq 30 ]; then
            print_error "PostgreSQL failed to start"
            docker-compose logs postgres
            exit 1
        fi
    done
    
    # Start Keycloak
    print_status "Starting Keycloak..."
    docker-compose up -d keycloak
    
    # Wait for Keycloak to be ready
    print_status "Waiting for Keycloak to start (this may take 2-3 minutes)..."
    for i in {1..90}; do
        if curl -f http://localhost:8090/health/ready >/dev/null 2>&1; then
            print_status "Keycloak is ready ✓"
            break
        fi
        echo -n "."
        sleep 2
        if [ $i -eq 90 ]; then
            print_error "Keycloak failed to start"
            print_status "Showing Keycloak logs:"
            docker-compose logs keycloak
            exit 1
        fi
    done
    
    # Start remaining services
    print_status "Starting remaining services..."
    docker-compose up -d
    
    print_status "All services started successfully ✓"
}

# Show service status
show_status() {
    print_status "Service Status:"
    echo "==============="
    docker-compose ps
    echo ""
    
    print_status "Service URLs:"
    echo "============="
    echo "🔐 Keycloak Admin: http://localhost:8090 (admin/admin)"
    echo "🔐 Auth Service Realm: http://localhost:8090/realms/auth-service"
    echo "🚀 Auth Service API: http://localhost:8080"
    echo "📊 Grafana: http://localhost:3000 (admin/admin)"
    echo "📈 Prometheus: http://localhost:9090"
    echo "🔍 Jaeger: http://localhost:16686"
    echo ""
    echo "Test credentials:"
    echo "- Admin user: admin/admin"
    echo "- Test user: testuser/testuser"
    echo "- Client: auth-service-client / auth-service-secret"
}

# Show logs for debugging
show_logs() {
    print_status "Recent logs from Keycloak:"
    echo "=========================="
    docker-compose logs --tail=50 keycloak
    echo ""
    
    print_status "Recent logs from PostgreSQL:"
    echo "============================"
    docker-compose logs --tail=20 postgres
}

# Main execution
main() {
    echo "Starting Keycloak troubleshooting process..."
    echo ""
    
    check_docker
    check_resources
    fix_permissions
    cleanup
    start_services
    show_status
    
    print_status "🎉 Keycloak setup completed successfully!"
    print_status "If you encounter issues, run: docker-compose logs keycloak"
    
    # Ask if user wants to see logs
    echo ""
    read -p "Do you want to see recent logs? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        show_logs
    fi
}

# Handle script arguments
case "${1:-}" in
    "cleanup")
        cleanup
        ;;
    "logs")
        show_logs
        ;;
    "status")
        show_status
        ;;
    *)
        main
        ;;
esac