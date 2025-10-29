#!/bin/bash

# Test Reset Password Functionality
# This script tests the reset password endpoint with various scenarios

set -e

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

# Configuration
BASE_URL="http://localhost:8080"
REALM="auth-service"
CLIENT_ID="auth-service-client"
CLIENT_SECRET="auth-service-secret"

echo "🔧 Testing Reset Password Functionality"
echo "======================================"

# Check if auth service is running
print_status "Checking if auth service is running..."
if ! curl -s "$BASE_URL/health" > /dev/null; then
    print_error "Auth service is not running on $BASE_URL"
    print_status "Please start the service with: make docker-up"
    exit 1
fi
print_status "Auth service is running ✓"

# Test 1: Reset password with username
print_status "Test 1: Reset password with username (admin)"
echo "=============================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "username": "admin",
    "redirect_uri": "http://localhost:8080/auth/reset-password-complete"
  }')

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "200" ]; then
    print_status "✓ Reset password with username succeeded"
else
    print_warning "⚠ Reset password with username returned HTTP $http_code"
    echo "Response: $response_body"
fi

echo ""

# Test 2: Reset password with email
print_status "Test 2: Reset password with email (admin@example.com)"
echo "===================================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "email": "admin@example.com",
    "redirect_uri": "http://localhost:8080/auth/reset-password-complete"
  }')

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "200" ]; then
    print_status "✓ Reset password with email succeeded"
else
    print_warning "⚠ Reset password with email returned HTTP $http_code"
    echo "Response: $response_body"
fi

echo ""

# Test 3: Reset password with invalid user
print_status "Test 3: Reset password with invalid user"
echo "========================================"

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "username": "nonexistent_user",
    "redirect_uri": "http://localhost:8080/auth/reset-password-complete"
  }')

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "500" ]; then
    print_status "✓ Reset password with invalid user correctly returned error"
else
    print_warning "⚠ Reset password with invalid user returned HTTP $http_code (expected 500)"
fi

echo ""

# Test 4: Reset password without username or email
print_status "Test 4: Reset password without username or email"
echo "==============================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "redirect_uri": "http://localhost:8080/auth/reset-password-complete"
  }')

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "400" ]; then
    print_status "✓ Reset password without username/email correctly returned 400"
else
    print_warning "⚠ Reset password without username/email returned HTTP $http_code (expected 400)"
fi

echo ""

# Test 5: Reset password with testuser
print_status "Test 5: Reset password with testuser"
echo "===================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "username": "testuser",
    "redirect_uri": "http://localhost:8080/auth/reset-password-complete"
  }')

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "200" ]; then
    print_status "✓ Reset password with testuser succeeded"
else
    print_warning "⚠ Reset password with testuser returned HTTP $http_code"
    echo "Response: $response_body"
fi

echo ""
print_status "🎉 Reset password testing completed!"
print_status ""
print_status "Note: If you see JSON parsing errors, check:"
print_status "1. Keycloak is running and accessible"
print_status "2. The auth-service realm exists in Keycloak"
print_status "3. Users exist in the realm"
print_status "4. Client credentials are correct"