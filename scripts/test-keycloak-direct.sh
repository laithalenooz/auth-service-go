#!/bin/bash

# Test Keycloak execute-actions-email API directly
# This script demonstrates the correct JSON format for the API

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
KEYCLOAK_URL="http://localhost:8090"
REALM="auth-service"
CLIENT_ID="auth-service-client"
CLIENT_SECRET="auth-service-secret"
USERNAME="admin"
PASSWORD="admin"

echo "🔧 Testing Keycloak execute-actions-email API directly"
echo "===================================================="

# Step 1: Get admin token
print_status "Step 1: Getting admin token..."
TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    print_error "Failed to get access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

print_status "✓ Got admin token"

# Step 2: Get user ID for admin user in auth-service realm
print_status "Step 2: Getting user ID for admin user..."
USERS_RESPONSE=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/users?username=admin" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json")

USER_ID=$(echo "$USERS_RESPONSE" | jq -r '.[0].id')

if [ "$USER_ID" = "null" ] || [ -z "$USER_ID" ]; then
    print_error "Failed to get user ID"
    echo "Response: $USERS_RESPONSE"
    exit 1
fi

print_status "✓ Got user ID: $USER_ID"

# Step 3: Test execute-actions-email with correct format
print_status "Step 3: Testing execute-actions-email API..."
print_status "URL: $KEYCLOAK_URL/admin/realms/$REALM/users/$USER_ID/execute-actions-email?client_id=$CLIENT_ID&redirect_uri=http://localhost:8080/reset-complete"
print_status "Body: [\"UPDATE_PASSWORD\"]"

RESET_RESPONSE=$(curl -s -w "%{http_code}" -X PUT \
  "$KEYCLOAK_URL/admin/realms/$REALM/users/$USER_ID/execute-actions-email?client_id=$CLIENT_ID&redirect_uri=http://localhost:8080/reset-complete" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '["UPDATE_PASSWORD"]')

HTTP_CODE="${RESET_RESPONSE: -3}"
RESPONSE_BODY="${RESET_RESPONSE%???}"

echo "HTTP Status: $HTTP_CODE"
echo "Response Body: '$RESPONSE_BODY'"

if [ "$HTTP_CODE" = "204" ]; then
    print_status "✅ SUCCESS! execute-actions-email API worked correctly"
    print_status "The correct format is:"
    print_status "- Method: PUT"
    print_status "- Body: [\"UPDATE_PASSWORD\"] (JSON array)"
    print_status "- Query params: ?client_id=xxx&redirect_uri=xxx"
elif [ "$HTTP_CODE" = "400" ]; then
    print_error "❌ HTTP 400 - Bad Request (JSON parsing error)"
    echo "This indicates the JSON format is still incorrect"
else
    print_error "❌ HTTP $HTTP_CODE - Unexpected response"
    echo "Response: $RESPONSE_BODY"
fi

echo ""
print_status "🎯 Key Findings:"
print_status "- Keycloak expects: [\"UPDATE_PASSWORD\"] in request body"
print_status "- NOT: {\"actions\": [\"UPDATE_PASSWORD\"]}"
print_status "- client_id and redirect_uri go in query parameters"
print_status "- Expected success response: HTTP 204 No Content"