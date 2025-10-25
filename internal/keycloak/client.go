package keycloak

import (
	"bytes"
	"context"
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
)

const (
	tracerName = "keycloak-client"
)

// Client represents an instrumented Keycloak client
type Client struct {
	config     *config.KeycloakConfig
	httpClient *http.Client
	tracer     trace.Tracer
	baseURL    string
	adminToken *AdminToken
}

// AdminToken holds admin authentication token
type AdminToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"-"`
}

// User represents a Keycloak user
type User struct {
	ID              string            `json:"id,omitempty"`
	Username        string            `json:"username"`
	Email           string            `json:"email,omitempty"`
	FirstName       string            `json:"firstName,omitempty"`
	LastName        string            `json:"lastName,omitempty"`
	Enabled         bool              `json:"enabled"`
	EmailVerified   bool              `json:"emailVerified"`
	CreatedTimestamp int64            `json:"createdTimestamp,omitempty"`
	Attributes      map[string][]string `json:"attributes,omitempty"`
	Groups          []string          `json:"groups,omitempty"`
	RealmRoles      []string          `json:"realmRoles,omitempty"`
}

// TokenIntrospection represents token introspection response
type TokenIntrospection struct {
	Active    bool              `json:"active"`
	ClientID  string            `json:"client_id,omitempty"`
	Username  string            `json:"username,omitempty"`
	TokenType string            `json:"token_type,omitempty"`
	Exp       int64             `json:"exp,omitempty"`
	Iat       int64             `json:"iat,omitempty"`
	Nbf       int64             `json:"nbf,omitempty"`
	Sub       string            `json:"sub,omitempty"`
	Aud       string            `json:"aud,omitempty"`
	Iss       string            `json:"iss,omitempty"`
	Jti       string            `json:"jti,omitempty"`
	Scope     string            `json:"scope,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// NewClient creates a new instrumented Keycloak client
func NewClient(cfg *config.KeycloakConfig) *Client {
	// Create HTTP client with OpenTelemetry instrumentation
	httpClient := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
				return fmt.Sprintf("keycloak %s %s", r.Method, r.URL.Path)
			}),
		),
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		tracer:     otel.Tracer(tracerName),
		baseURL:    strings.TrimSuffix(cfg.BaseURL, "/"),
	}
}

// ensureAdminToken ensures we have a valid admin token
func (c *Client) ensureAdminToken(ctx context.Context) error {
	ctx, span := c.tracer.Start(ctx, "keycloak.admin_token.ensure",
		trace.WithAttributes(
			attribute.String("keycloak.realm", c.config.Realm),
			attribute.String("keycloak.client_id", c.config.ClientID),
		),
	)
	defer span.End()

	// Check if we have a valid token
	if c.adminToken != nil && time.Now().Before(c.adminToken.ExpiresAt.Add(-30*time.Second)) {
		span.SetAttributes(attribute.Bool("keycloak.admin_token.cached", true))
		return nil
	}

	// Acquire new admin token
	span.SetAttributes(attribute.Bool("keycloak.admin_token.refresh", true))
	return c.acquireAdminToken(ctx)
}

// acquireAdminToken acquires a new admin token
func (c *Client) acquireAdminToken(ctx context.Context) error {
	ctx, span := c.tracer.Start(ctx, "keycloak.admin_token.acquire",
		trace.WithAttributes(
			attribute.String("keycloak.realm", c.config.Realm),
			attribute.String("keycloak.client_id", c.config.ClientID),
		),
	)
	defer span.End()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", c.config.ClientID)
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}
	data.Set("username", c.config.AdminUsername)
	data.Set("password", c.config.AdminPassword)

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

	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	c.adminToken = &token

	span.SetAttributes(
		attribute.Int("keycloak.token.expires_in", token.ExpiresIn),
		attribute.String("keycloak.token.type", token.TokenType),
	)
	span.SetStatus(codes.Ok, "admin token acquired")

	return nil
}

// CreateUser creates a new user in Keycloak
func (c *Client) CreateUser(ctx context.Context, user *User) (*User, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.create",
		trace.WithAttributes(
			attribute.String("keycloak.realm", c.config.Realm),
			attribute.String("keycloak.user.username", user.Username),
			attribute.String("keycloak.user.email", user.Email),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users", c.baseURL, c.config.Realm)

	body, err := json.Marshal(user)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal user")
		return nil, fmt.Errorf("failed to marshal user: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", userURL, bytes.NewReader(body))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create user request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", userURL),
	)

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("failed to create user: HTTP %d: %s", resp.StatusCode, string(body))
	}

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

	// Fetch the created user
	createdUser, err := c.GetUser(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fetch created user")
		return nil, fmt.Errorf("failed to fetch created user: %w", err)
	}

	span.SetAttributes(attribute.String("keycloak.user.id", createdUser.ID))
	span.SetStatus(codes.Ok, "user created successfully")

	return createdUser, nil
}

// GetUser retrieves a user by ID
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.user.get",
		trace.WithAttributes(
			attribute.String("keycloak.realm", c.config.Realm),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, c.config.Realm, userID)

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

// IntrospectToken introspects a token
func (c *Client) IntrospectToken(ctx context.Context, token, tokenTypeHint string) (*TokenIntrospection, error) {
	ctx, span := c.tracer.Start(ctx, "keycloak.token.introspect",
		trace.WithAttributes(
			attribute.String("keycloak.realm", c.config.Realm),
			attribute.String("keycloak.token.type_hint", tokenTypeHint),
		),
	)
	defer span.End()

	if err := c.ensureAdminToken(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to ensure admin token")
		return nil, err
	}

	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", c.baseURL, c.config.Realm)

	data := url.Values{}
	data.Set("token", token)
	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create introspect request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.adminToken.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.String("http.method", "POST"),
		attribute.String("http.url", introspectURL),
	)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("failed to introspect token: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var introspection TokenIntrospection
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode response")
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("keycloak.token.active", introspection.Active),
		attribute.String("keycloak.token.client_id", introspection.ClientID),
		attribute.String("keycloak.token.username", introspection.Username),
	)
	span.SetStatus(codes.Ok, "token introspected successfully")

	return &introspection, nil
}