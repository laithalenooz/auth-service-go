#!/bin/bash

# Test Impersonation Functionality
# This script tests the user impersonation endpoint

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
KEYCLOAK_URL="http://localhost:8090"
REALM="auth-service"
CLIENT_ID="auth-service-client"
CLIENT_SECRET="auth-service-secret"

echo "🔧 Testing User Impersonation Functionality"
echo "==========================================="

# Check if auth service is running
print_status "Checking if auth service is running..."
if ! curl -s "$BASE_URL/health" > /dev/null; then
    print_error "Auth service is not running on $BASE_URL"
    print_status "Please start the service with: make docker-up"
    exit 1
fi
print_status "Auth service is running ✓"

# Step 1: Get admin user ID from Keycloak
print_status "Step 1: Getting admin user ID from Keycloak..."

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    print_error "Failed to get admin token from Keycloak"
    exit 1
fi

# Get admin user ID from auth-service realm
ADMIN_USER_ID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/users?username=admin" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

if [ "$ADMIN_USER_ID" = "null" ] || [ -z "$ADMIN_USER_ID" ]; then
    print_error "Failed to get admin user ID from auth-service realm"
    exit 1
fi

print_status "✓ Got admin user ID: $ADMIN_USER_ID"

# Step 2: Test impersonation with valid user
print_status "Step 2: Testing impersonation with admin user"
echo "=============================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/impersonate" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d "{
    \"target_user_id\": \"$ADMIN_USER_ID\",
    \"target_client_id\": \"$CLIENT_ID\"
  }")

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "200" ]; then
    print_status "✅ Impersonation succeeded!"
    
    # Extract access token for further testing
    ACCESS_TOKEN=$(echo "$response_body" | jq -r '.access_token')
    if [ "$ACCESS_TOKEN" != "null" ] && [ -n "$ACCESS_TOKEN" ]; then
        print_status "✓ Received access token: ${ACCESS_TOKEN:0:50}..."
        
        # Test the impersonated token
        print_status "Step 3: Testing impersonated token..."
        token_test=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/tokens/verify" \
          -H "Content-Type: application/json" \
          -H "X-Realm-Name: $REALM" \
          -H "X-Client-Id: $CLIENT_ID" \
          -H "X-Client-Secret: $CLIENT_SECRET" \
          -d "{\"token\": \"$ACCESS_TOKEN\"}")
        
        token_http_code="${token_test: -3}"
        token_response="${token_test%???}"
        
        if [ "$token_http_code" = "200" ]; then
            print_status "✅ Impersonated token is valid!"
            echo "Token details: $token_response"
        else
            print_warning "⚠ Impersonated token verification failed (HTTP $token_http_code)"
        fi
    fi
else
    print_error "❌ Impersonation failed (HTTP $http_code)"
    echo "Response: $response_body"
fi

echo ""

# Step 4: Test impersonation with invalid user ID
print_status "Step 4: Testing impersonation with invalid user ID"
echo "=================================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/impersonate" \
  -H "Content-Type: application/json" \
  -H "X-Realm-Name: $REALM" \
  -H "X-Client-Id: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "target_user_id": "invalid-user-id",
    "target_client_id": "'$CLIENT_ID'"
  }')

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "500" ]; then
    print_status "✅ Correctly rejected invalid user ID"
else
    print_warning "⚠ Expected HTTP 500 for invalid user ID, got $http_code"
fi

echo ""

# Step 5: Test impersonation without required headers
print_status "Step 5: Testing impersonation without required headers"
echo "====================================================="

response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/v1/auth/impersonate" \
  -H "Content-Type: application/json" \
  -d "{
    \"target_user_id\": \"$ADMIN_USER_ID\",
    \"target_client_id\": \"$CLIENT_ID\"
  }")

http_code="${response: -3}"
response_body="${response%???}"

echo "HTTP Status: $http_code"
echo "Response: $response_body"

if [ "$http_code" = "400" ]; then
    print_status "✅ Correctly rejected request without headers"
else
    print_warning "⚠ Expected HTTP 400 for missing headers, got $http_code"
fi

echo ""
print_status "🎉 Impersonation testing completed!"
print_status ""
print_status "Summary:"
print_status "- Impersonation endpoint: POST /api/v1/auth/impersonate"
print_status "- Required headers: X-Realm-Name, X-Client-Id, X-Client-Secret"
print_status "- Request body: {\"target_user_id\": \"user-id\", \"target_client_id\": \"client-id\"}"
print_status "- Response: OAuth2 token response with access_token, refresh_token, etc."
print_status ""
print_status "OAuth2 Token Exchange Grant Type: urn:ietf:params:oauth:grant-type:token-exchange"
print_status "Keycloak API: /realms/{realm}/protocol/openid-connect/token"