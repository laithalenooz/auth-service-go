package keycloak

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/laithalenooz/auth-service-go/internal/config"
	"github.com/laithalenooz/auth-service-go/internal/metrics"
)

const tracerName = "keycloak-client"

// Client represents a Keycloak HTTP client with OpenTelemetry instrumentation
type Client struct {
	baseURL       string
	config        *config.KeycloakConfig
	httpClient    *http.Client
	tracer        trace.Tracer
	adminToken    *AdminToken
	adminTokenKey string // Track which realm/client the current token is for
	metrics       *metrics.Metrics
}

// AdminToken represents an admin access token
type AdminToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"-"`
}

// User represents a Keycloak user
type User struct {
	ID                string                 `json:"id,omitempty"`
	Username          string                 `json:"username"`
	Email             string                 `json:"email,omitempty"`
	FirstName         string                 `json:"firstName,omitempty"`
	LastName          string                 `json:"lastName,omitempty"`
	Enabled           bool                   `json:"enabled"`
	EmailVerified     bool                   `json:"emailVerified"`
	CreatedTimestamp  int64                  `json:"createdTimestamp,omitempty"`
	Attributes        map[string]interface{} `json:"attributes,omitempty"`
	RequiredActions   []string               `json:"requiredActions,omitempty"`
	Groups            []string               `json:"groups,omitempty"`
	RealmRoles        []string               `json:"realmRoles,omitempty"`
	ClientRoles       map[string]interface{} `json:"clientRoles,omitempty"`
	Credentials       []Credential           `json:"credentials,omitempty"`
}

// Credential represents user credentials
type Credential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// AudienceField handles both string and array audience values
type AudienceField []string

// UnmarshalJSON implements custom unmarshaling for audience field
func (a *AudienceField) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as array first
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*a = AudienceField(arr)
		return nil
	}
	
	// If that fails, try as string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*a = AudienceField([]string{str})
		return nil
	}
	
	return fmt.Errorf("audience field must be string or array of strings")
}

// String returns the first audience value or empty string
func (a AudienceField) String() string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}

// TokenIntrospection represents token introspection response
type TokenIntrospection struct {
	Active    bool          `json:"active"`
	ClientID  string        `json:"client_id,omitempty"`
	Username  string        `json:"username,omitempty"`
	TokenType string        `json:"token_type,omitempty"`
	Exp       int64         `json:"exp,omitempty"`
	Iat       int64         `json:"iat,omitempty"`
	Sub       string        `json:"sub,omitempty"`
	Aud       AudienceField `json:"aud,omitempty"`
	Iss       string        `json:"iss,omitempty"`
	Scope     string        `json:"scope,omitempty"`
}



// NewClient creates a new Keycloak client with OpenTelemetry instrumentation
func NewClient(config *config.KeycloakConfig, m *metrics.Metrics) *Client {
	// Create HTTP client with OpenTelemetry instrumentation
	httpClient := &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   30 * time.Second,
	}

	return &Client{
		baseURL:    config.BaseURL,
		config:     config,
		httpClient: httpClient,
		tracer:     otel.Tracer(tracerName),
		metrics:    m,
	}
}

// ensureAdminToken ensures we have a valid admin token
func (c *Client) ensureAdminToken(ctx context.Context, realm, clientID, clientSecret string) error {
	// Check if we have a valid token for this specific realm/client combination
	tokenKey := fmt.Sprintf("%s:%s", realm, clientID)
	if c.adminToken != nil && c.adminTokenKey == tokenKey && time.Now().Before(c.adminToken.ExpiresAt.Add(-30*time.Second)) {
		return nil
	}

	// Acquire new admin token for the specific realm/client
	return c.acquireAdminToken(ctx, realm, clientID, clientSecret)
}

// acquireAdminToken acquires an admin access token
func (c *Client) acquireAdminToken(ctx context.Context, realm, clientID, clientSecret string) error {
	ctx, span := c.tracer.Start(ctx, "keycloak.admin_token.acquire",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.client_id", clientID),
		),
	)
	defer span.End()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realm)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return fmt.Errorf("failed to acquire admin token: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", tokenURL),
	)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return fmt.Errorf("failed to acquire admin token: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var token AdminToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Set expiration time
	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	c.adminToken = &token
	c.adminTokenKey = fmt.Sprintf("%s:%s", realm, clientID)

	span.SetAttributes(
		attribute.String("keycloak.token.type", token.TokenType),
		attribute.Int("keycloak.token.expires_in", token.ExpiresIn),
	)
	span.SetStatus(codes.Ok, "admin token acquired successfully")

	return nil
}

// CreateUser creates a new user in Keycloak
func (c *Client) CreateUser(ctx context.Context, realm, clientID, clientSecret string, user *User) (*User, error) {
	start := time.Now()
	ctx, span := c.tracer.Start(ctx, "keycloak.user.create",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.user.username", user.Username),
			attribute.String("keycloak.user.email", user.Email),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		c.metrics.RecordKeycloakError("create_user", "admin_token_error")
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users", c.baseURL, realm)

	userJSON, err := json.Marshal(user)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal user")
		c.metrics.RecordKeycloakError("create_user", "marshal_error")
		return nil, fmt.Errorf("failed to marshal user: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", userURL, bytes.NewBuffer(userJSON))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		c.metrics.RecordKeycloakError("create_user", "request_creation_error")
		return nil, fmt.Errorf("failed to create user request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		c.metrics.RecordKeycloakRequest("create_user", "error", duration)
		c.metrics.RecordKeycloakError("create_user", "http_error")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	statusCode := fmt.Sprintf("%d", resp.StatusCode)
	c.metrics.RecordKeycloakRequest("create_user", statusCode, duration)

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		c.metrics.RecordKeycloakError("create_user", "http_status_error")
		return nil, fmt.Errorf("failed to create user: HTTP %d: %s", resp.StatusCode, string(body))
	}

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", userURL),
	)

	// Extract user ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		span.SetStatus(codes.Error, "missing location header")
		return nil, fmt.Errorf("missing location header in create user response")
	}

	// Extract user ID from location URL
	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		span.SetStatus(codes.Error, "invalid location header")
		return nil, fmt.Errorf("invalid location header: %s", location)
	}
	userID := parts[len(parts)-1]

	// Return user with ID
	createdUser := *user
	createdUser.ID = userID

	span.SetAttributes(attribute.String("keycloak.user.id", userID))
	span.SetStatus(codes.Ok, "user created successfully")

	return &createdUser, nil
}

// GetUser retrieves a user by ID
func (c *Client) GetUser(ctx context.Context, realm, clientID, clientSecret, userID string) (*User, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.get",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, realm, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create get user request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "GET"),
		attribute.String("http.url", userURL),
	)

	if resp.StatusCode == http.StatusNotFound {
		span.SetStatus(codes.Error, "user not found")
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("failed to get user: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, fmt.Errorf("failed to decode user response: %w", err)
	}

	span.SetAttributes(
		attribute.String("keycloak.user.username", user.Username),
		attribute.String("keycloak.user.email", user.Email),
	)
	span.SetStatus(codes.Ok, "user retrieved successfully")

	return &user, nil
}

// IntrospectToken introspects a token to validate it
func (c *Client) IntrospectToken(ctx context.Context, token string) (*TokenIntrospection, error) {
	start := time.Now()
	ctx, span := c.tracer.Start(ctx, "keycloak.token.introspect",
		trace.WithAttributes(
			attribute.String("keycloak.realm", c.config.Realm),
			attribute.String("keycloak.client_id", c.config.ClientID),
		),
	)
	defer span.End()

	// Hash the token for logging (don't log the actual token)
	tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	span.SetAttributes(attribute.String("keycloak.token.hash", tokenHash[:16]))

	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", c.baseURL, c.config.Realm)

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		c.metrics.RecordKeycloakError("introspect_token", "request_creation_error")
		return nil, fmt.Errorf("failed to create introspect request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		c.metrics.RecordKeycloakRequest("introspect_token", "error", duration)
		c.metrics.RecordKeycloakError("introspect_token", "http_error")
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	statusCode := fmt.Sprintf("%d", resp.StatusCode)
	c.metrics.RecordKeycloakRequest("introspect_token", statusCode, duration)

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", introspectURL),
	)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		c.metrics.RecordKeycloakError("introspect_token", "http_status_error")
		return nil, fmt.Errorf("failed to introspect token: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var introspection TokenIntrospection
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		c.metrics.RecordKeycloakError("introspect_token", "decode_error")
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("keycloak.token.active", introspection.Active),
		attribute.String("keycloak.token.username", introspection.Username),
		attribute.String("keycloak.token.client_id", introspection.ClientID),
	)
	span.SetStatus(codes.Ok, "token introspected successfully")

	return &introspection, nil
}

// DeleteUser deletes a user by ID
func (c *Client) DeleteUser(ctx context.Context, realm, clientID, clientSecret, userID string) error {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.delete",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		return err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, realm, userID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", userURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return fmt.Errorf("failed to create delete user request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "DELETE"),
		attribute.String("http.url", userURL),
	)

	if resp.StatusCode == http.StatusNotFound {
		span.SetStatus(codes.Error, "user not found")
		return fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return fmt.Errorf("failed to delete user: HTTP %d: %s", resp.StatusCode, string(body))
	}

	span.SetStatus(codes.Ok, "user deleted successfully")
	return nil
}

// ListUsers lists users with pagination and search
func (c *Client) ListUsers(ctx context.Context, realm, clientID, clientSecret string, page, pageSize int, search, email, username string) ([]*User, int, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.list",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.Int("page", page),
			attribute.Int("page_size", pageSize),
			attribute.String("search", search),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		return nil, 0, err
	}

	// Build query parameters
	params := url.Values{}
	if page > 0 {
		params.Set("first", fmt.Sprintf("%d", (page-1)*pageSize))
	}
	if pageSize > 0 {
		params.Set("max", fmt.Sprintf("%d", pageSize))
	}
	if search != "" {
		params.Set("search", search)
	}
	if email != "" {
		params.Set("email", email)
	}
	if username != "" {
		params.Set("username", username)
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users?%s", c.baseURL, c.config.Realm, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, 0, fmt.Errorf("failed to create list users request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "GET"),
		attribute.String("http.url", userURL),
	)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, 0, fmt.Errorf("failed to list users: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var users []*User
	if decodeErr := json.NewDecoder(resp.Body).Decode(&users); decodeErr != nil {
		span.RecordError(decodeErr)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, 0, fmt.Errorf("failed to decode users response: %w", decodeErr)
	}

	// Get total count (requires separate request)
	totalCount, err := c.getUsersCount(ctx, search, email, username)
	if err != nil {
		span.AddEvent("failed to get users count", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		// Don't fail the request, just use the returned count
		totalCount = len(users)
	}

	span.SetAttributes(
		attribute.Int("keycloak.users.count", len(users)),
		attribute.Int("keycloak.users.total", totalCount),
	)
	span.SetStatus(codes.Ok, "users listed successfully")

	return users, totalCount, nil
}

// getUsersCount gets the total count of users
func (c *Client) getUsersCount(ctx context.Context, search, email, username string) (int, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.count")
	defer span.End()

	// Build query parameters
	params := url.Values{}
	if search != "" {
		params.Set("search", search)
	}
	if email != "" {
		params.Set("email", email)
	}
	if username != "" {
		params.Set("username", username)
	}

	countURL := fmt.Sprintf("%s/admin/realms/%s/users/count?%s", c.baseURL, c.config.Realm, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", countURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return 0, fmt.Errorf("failed to create count request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return 0, fmt.Errorf("failed to get users count: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return 0, fmt.Errorf("failed to get users count: HTTP %d", resp.StatusCode)
	}

	var count int
	if err := json.NewDecoder(resp.Body).Decode(&count); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return 0, fmt.Errorf("failed to decode count response: %w", err)
	}

	span.SetAttributes(attribute.Int("keycloak.users.total_count", count))
	span.SetStatus(codes.Ok, "users count retrieved")

	return count, nil
}

// RefreshToken refreshes an access token using a refresh token
func (c *Client) RefreshToken(ctx context.Context, realm, refreshToken, clientID, clientSecret string) (*TokenResponse, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.token.refresh",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.client_id", clientID),
		),
	)
	defer span.End()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realm)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", tokenURL),
	)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("failed to refresh token: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	span.SetAttributes(
		attribute.String("keycloak.token.type", tokenResponse.TokenType),
		attribute.Int("keycloak.token.expires_in", tokenResponse.ExpiresIn),
	)
	span.SetStatus(codes.Ok, "token refreshed successfully")

	return &tokenResponse, nil
}

// Login authenticates a user and returns tokens
func (c *Client) Login(ctx context.Context, realm, username, password, clientID, clientSecret string, scopes []string) (*TokenResponse, *User, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.login",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.client_id", clientID),
			attribute.String("keycloak.username", username),
		),
	)
	defer span.End()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, nil, fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, nil, fmt.Errorf("failed to login: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", tokenURL),
	)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, nil, fmt.Errorf("failed to login: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Get user info using the access token
	user, err := c.getUserInfo(ctx, tokenResponse.AccessToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get user info")
		// Don't fail the login if we can't get user info, just log the error
		user = &User{Username: username}
	}

	span.SetAttributes(
		attribute.String("keycloak.token.type", tokenResponse.TokenType),
		attribute.Int("keycloak.token.expires_in", tokenResponse.ExpiresIn),
	)
	span.SetStatus(codes.Ok, "login successful")

	return &tokenResponse, user, nil
}

// Logout revokes the refresh token
func (c *Client) Logout(ctx context.Context, realm, refreshToken, clientID, clientSecret string) error {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.logout",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.client_id", clientID),
		),
	)
	defer span.End()

	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", c.baseURL, realm)

	data := url.Values{}
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", logoutURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return fmt.Errorf("failed to logout: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", logoutURL),
	)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return fmt.Errorf("failed to logout: HTTP %d: %s", resp.StatusCode, string(body))
	}

	span.SetStatus(codes.Ok, "logout successful")
	return nil
}

// getUserInfo retrieves user information using an access token
func (c *Client) getUserInfo(ctx context.Context, accessToken string) (*User, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.info")
	defer span.End()

	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", c.baseURL, c.config.Realm)

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("failed to get user info: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var userInfo struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	user := &User{
		ID:            userInfo.Sub,
		Username:      userInfo.PreferredUsername,
		Email:         userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		FirstName:     userInfo.GivenName,
		LastName:      userInfo.FamilyName,
		Enabled:       true,
	}

	span.SetStatus(codes.Ok, "user info retrieved successfully")
	return user, nil
}

// TokenResponse represents the token refresh response
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

// Register creates a new user account in Keycloak
func (c *Client) Register(ctx context.Context, realm, clientID, clientSecret, username, email, firstName, lastName, password string, emailVerified bool, attributes map[string]interface{}) (*User, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.register")
	defer span.End()

	span.SetAttributes(
		attribute.String("keycloak.realm", realm),
		attribute.String("keycloak.username", username),
		attribute.String("keycloak.email", email),
		attribute.Bool("keycloak.email_verified", emailVerified),
	)

	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get admin token")
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	user := &User{
		Username:      username,
		Email:         email,
		FirstName:     firstName,
		LastName:      lastName,
		Enabled:       true,
		EmailVerified: emailVerified,
		Attributes:    attributes,
		Credentials: []Credential{
			{
				Type:      "password",
				Value:     password,
				Temporary: false,
			},
		},
	}

	// Create the user using the existing CreateUser method
	createdUser, err := c.CreateUser(ctx, realm, clientID, clientSecret, user)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create user")
		return nil, fmt.Errorf("failed to register user: %w", err)
	}

	span.SetStatus(codes.Ok, "user registered successfully")
	return createdUser, nil
}

// ResetPassword initiates a password reset for a user
func (c *Client) ResetPassword(ctx context.Context, realm, username, email, clientID, clientSecret, redirectURI string) error {
	ctx, span := c.tracer.Start(ctx, "keycloak.reset_password")
	defer span.End()

	span.SetAttributes(
		attribute.String("keycloak.realm", realm),
		attribute.String("keycloak.username", username),
		attribute.String("keycloak.email", email),
		attribute.String("keycloak.client_id", clientID),
	)

	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get admin token")
		return fmt.Errorf("failed to get admin token: %w", err)
	}

	// First, find the user by username or email
	var userID string
	if username != "" {
		users, _, err := c.ListUsers(ctx, realm, clientID, clientSecret, 0, 1, "", "", username)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to find user by username")
			return fmt.Errorf("failed to find user by username: %w", err)
		}
		if len(users) == 0 {
			span.SetStatus(codes.Error, "user not found")
			return fmt.Errorf("user not found with username: %s", username)
		}
		userID = users[0].ID
	} else if email != "" {
		users, _, err := c.ListUsers(ctx, realm, clientID, clientSecret, 0, 1, "", email, "")
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to find user by email")
			return fmt.Errorf("failed to find user by email: %w", err)
		}
		if len(users) == 0 {
			span.SetStatus(codes.Error, "user not found")
			return fmt.Errorf("user not found with email: %s", email)
		}
		userID = users[0].ID
	} else {
		span.SetStatus(codes.Error, "username or email required")
		return fmt.Errorf("username or email is required for password reset")
	}

	// Send password reset email using Keycloak Admin API
	resetURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/execute-actions-email", c.baseURL, realm, userID)
	
	// Add query parameters for client_id and redirect_uri if provided
	params := url.Values{}
	if clientID != "" {
		params.Add("client_id", clientID)
	}
	if redirectURI != "" {
		params.Add("redirect_uri", redirectURI)
	}
	if len(params) > 0 {
		resetURL += "?" + params.Encode()
	}

	// The body should be a simple JSON array of actions
	actions := []string{"UPDATE_PASSWORD"}
	jsonData, err := json.Marshal(actions)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal request")
		return fmt.Errorf("failed to marshal reset password request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", resetURL, bytes.NewBuffer(jsonData))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return fmt.Errorf("failed to create reset password request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return fmt.Errorf("failed to send reset password request: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "PUT"),
		attribute.String("http.url", resetURL),
	)

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		
		// Log the request details for debugging
		span.SetAttributes(
			attribute.String("request.body", string(jsonData)),
			attribute.String("response.body", string(body)),
		)
		
		return fmt.Errorf("failed to reset password: HTTP %d: %s", resp.StatusCode, string(body))
	}

	span.SetStatus(codes.Ok, "password reset email sent")
	return nil
}

// VerifyToken verifies an access token by introspecting it
func (c *Client) VerifyToken(ctx context.Context, realm, token, clientID, clientSecret string) (*TokenIntrospection, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.token.verify",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.client_id", clientID),
		),
	)
	defer span.End()

	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", c.baseURL, realm)

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create verify token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", introspectURL),
	)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to read response")
		return nil, fmt.Errorf("failed to read verify token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("failed to verify token: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var introspection TokenIntrospection
	if err := json.Unmarshal(body, &introspection); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to parse response")
		return nil, fmt.Errorf("failed to parse verify token response: %w", err)
	}

	span.SetStatus(codes.Ok, "token verified successfully")
	return &introspection, nil
}

// ImpersonateUser performs user impersonation by creating a token for the target user
func (c *Client) ImpersonateUser(ctx context.Context, realm, clientID, clientSecret, targetUserID, targetClientID string) (*TokenResponse, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.impersonate_user",
		trace.WithAttributes(
			attribute.String("keycloak.realm", realm),
			attribute.String("keycloak.client_id", clientID),
			attribute.String("keycloak.target_user_id", targetUserID),
			attribute.String("keycloak.target_client_id", targetClientID),
		),
	)
	defer span.End()

	// Ensure we have admin token for the realm
	if err := c.ensureAdminToken(ctx, realm, clientID, clientSecret); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get admin token")
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	// First, verify the target user exists
	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, realm, targetUserID)
	
	userReq, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create user request")
		return nil, fmt.Errorf("failed to create user request: %w", err)
	}

	userReq.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)
	userReq.Header.Set("Content-Type", "application/json")

	userResp, err := c.httpClient.Do(userReq)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get user")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userResp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", userResp.StatusCode))
		return nil, fmt.Errorf("user not found: HTTP %d: %s", userResp.StatusCode, string(body))
	}

	// Parse user data to get username
	var user struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Enabled  bool   `json:"enabled"`
	}
	
	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to read user response")
		return nil, fmt.Errorf("failed to read user response: %w", err)
	}

	if err := json.Unmarshal(userBody, &user); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to parse user response")
		return nil, fmt.Errorf("failed to parse user response: %w", err)
	}

	if !user.Enabled {
		span.SetStatus(codes.Error, "user is disabled")
		return nil, fmt.Errorf("user %s is disabled", targetUserID)
	}

	// Create an impersonation token using Keycloak's token exchange with proper parameters
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realm)

	// Use token exchange with the admin token to impersonate the user
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("subject_token", c.adminToken.AccessToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("requested_subject", targetUserID)
	
	// Set audience if target client is specified
	if targetClientID != "" && targetClientID != clientID {
		data.Set("audience", targetClientID)
	}

	tokenReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create token request")
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := c.httpClient.Do(tokenReq)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "token request failed")
		return nil, fmt.Errorf("failed to get impersonation token: %w", err)
	}
	defer tokenResp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", tokenResp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", tokenURL),
	)

	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to read response")
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if tokenResp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", tokenResp.StatusCode))
		
		// Log the request details for debugging
		span.SetAttributes(
			attribute.String("request.body", data.Encode()),
			attribute.String("response.body", string(body)),
		)
		
		// If token exchange fails, try alternative approach using direct user token creation
		return c.createUserToken(ctx, realm, clientID, clientSecret, user.Username, targetClientID)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to parse response")
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	span.SetStatus(codes.Ok, "user impersonation successful")
	return &tokenResponse, nil
}

// createUserToken creates a token for a specific user using admin privileges
func (c *Client) createUserToken(ctx context.Context, realm, clientID, clientSecret, username, targetClientID string) (*TokenResponse, error) {
	// This is a fallback method that creates a token by temporarily setting a password
	// and then using password grant. This requires admin privileges.
	
	// First, set a temporary password for the user
	tempPassword := fmt.Sprintf("temp_%d", time.Now().UnixNano())
	
	// Get user by username
	usersURL := fmt.Sprintf("%s/admin/realms/%s/users?username=%s&exact=true", c.baseURL, realm, username)
	
	usersReq, err := http.NewRequestWithContext(ctx, "GET", usersURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create users request: %w", err)
	}

	usersReq.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)
	usersReq.Header.Set("Content-Type", "application/json")

	usersResp, err := c.httpClient.Do(usersReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer usersResp.Body.Close()

	if usersResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(usersResp.Body)
		return nil, fmt.Errorf("failed to get users: HTTP %d: %s", usersResp.StatusCode, string(body))
	}

	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}

	usersBody, err := io.ReadAll(usersResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read users response: %w", err)
	}

	if err := json.Unmarshal(usersBody, &users); err != nil {
		return nil, fmt.Errorf("failed to parse users response: %w", err)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user %s not found", username)
	}

	userID := users[0].ID

	// Clear any required actions that might prevent login
	clearActionsURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, realm, userID)
	
	clearActionsData := map[string]interface{}{
		"requiredActions": []string{}, // Clear all required actions
		"enabled":         true,
		"emailVerified":   true,
	}

	clearActionsJSON, err := json.Marshal(clearActionsData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal clear actions data: %w", err)
	}

	clearActionsReq, err := http.NewRequestWithContext(ctx, "PUT", clearActionsURL, bytes.NewBuffer(clearActionsJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create clear actions request: %w", err)
	}

	clearActionsReq.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)
	clearActionsReq.Header.Set("Content-Type", "application/json")

	clearActionsResp, err := c.httpClient.Do(clearActionsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to clear required actions: %w", err)
	}
	defer clearActionsResp.Body.Close()

	if clearActionsResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(clearActionsResp.Body)
		return nil, fmt.Errorf("failed to clear required actions: HTTP %d: %s", clearActionsResp.StatusCode, string(body))
	}

	// Set temporary password
	passwordURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", c.baseURL, realm, userID)
	
	passwordData := map[string]interface{}{
		"type":      "password",
		"value":     tempPassword,
		"temporary": false, // Set to false so user doesn't need to change it
	}

	passwordJSON, err := json.Marshal(passwordData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal password data: %w", err)
	}

	passwordReq, err := http.NewRequestWithContext(ctx, "PUT", passwordURL, bytes.NewBuffer(passwordJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create password request: %w", err)
	}

	passwordReq.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)
	passwordReq.Header.Set("Content-Type", "application/json")

	passwordResp, err := c.httpClient.Do(passwordReq)
	if err != nil {
		return nil, fmt.Errorf("failed to set password: %w", err)
	}
	defer passwordResp.Body.Close()

	if passwordResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(passwordResp.Body)
		return nil, fmt.Errorf("failed to set password: HTTP %d: %s", passwordResp.StatusCode, string(body))
	}

	// Now get token using password grant
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("username", username)
	data.Set("password", tempPassword)
	data.Set("scope", "openid profile email")

	tokenReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := c.httpClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get user token: %w", err)
	}
	defer tokenResp.Body.Close()

	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// Clean up: remove the password after getting the token
	go func() {
		// Use a background context for cleanup
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		// Remove the password by clearing credentials
		credentialsURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/credentials", c.baseURL, realm, userID)
		
		// Get current credentials
		credReq, _ := http.NewRequestWithContext(cleanupCtx, "GET", credentialsURL, nil)
		credReq.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)
		credReq.Header.Set("Content-Type", "application/json")
		
		credResp, err := c.httpClient.Do(credReq)
		if err == nil && credResp.StatusCode == http.StatusOK {
			defer credResp.Body.Close()
			
			var credentials []map[string]interface{}
			credBody, _ := io.ReadAll(credResp.Body)
			if json.Unmarshal(credBody, &credentials) == nil {
				// Delete each password credential
				for _, cred := range credentials {
					if credType, ok := cred["type"].(string); ok && credType == "password" {
						if credID, ok := cred["id"].(string); ok {
							deleteURL := fmt.Sprintf("%s/%s", credentialsURL, credID)
							deleteReq, _ := http.NewRequestWithContext(cleanupCtx, "DELETE", deleteURL, nil)
							deleteReq.Header.Set("Authorization", "Bearer "+c.adminToken.AccessToken)
							c.httpClient.Do(deleteReq)
						}
					}
				}
			}
		}
	}()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user token: HTTP %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResponse, nil
}