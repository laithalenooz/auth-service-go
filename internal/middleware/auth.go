package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/laithalenooz/auth-service-go/internal/cache"
	"github.com/laithalenooz/auth-service-go/internal/config"
	"github.com/laithalenooz/auth-service-go/internal/keycloak"
)

const (
	tracerName = "jwt-middleware"
	
	// Context keys
	UserIDKey     = "user_id"
	UsernameKey   = "username"
	RolesKey      = "roles"
	ClientIDKey   = "client_id"
	TokenClaimsKey = "token_claims"
)

// AuthMiddleware handles JWT token validation with OpenTelemetry tracing
type AuthMiddleware struct {
	config         *config.Config
	keycloakClient *keycloak.Client
	cacheClient    *cache.Client
	tracer         trace.Tracer
	jwksCache      map[string]*rsa.PublicKey
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string                 `json:"preferred_username"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	Name              string                 `json:"name"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	RealmAccess       RealmAccess            `json:"realm_access"`
	ResourceAccess    map[string]ClientRoles `json:"resource_access"`
	Scope             string                 `json:"scope"`
	ClientID          string                 `json:"azp"`
	SessionState      string                 `json:"session_state"`
	ACR               string                 `json:"acr"`
	AllowedOrigins    []string               `json:"allowed-origins"`
	Groups            []string               `json:"groups"`
}

// RealmAccess represents realm-level roles
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// ClientRoles represents client-specific roles
type ClientRoles struct {
	Roles []string `json:"roles"`
}

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// NewAuthMiddleware creates a new JWT authentication middleware
func NewAuthMiddleware(cfg *config.Config, kcClient *keycloak.Client, cacheClient *cache.Client) *AuthMiddleware {
	return &AuthMiddleware{
		config:         cfg,
		keycloakClient: kcClient,
		cacheClient:    cacheClient,
		tracer:         otel.Tracer(tracerName),
		jwksCache:      make(map[string]*rsa.PublicKey),
	}
}

// RequireAuth middleware that validates JWT tokens
func (am *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := am.tracer.Start(c.Request.Context(), "jwt.validate",
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.url", c.Request.URL.Path),
			),
		)
		defer span.End()

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			span.SetStatus(codes.Error, "missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check Bearer token format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			span.SetStatus(codes.Error, "invalid authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := tokenParts[1]
		span.SetAttributes(attribute.String("jwt.token_length", fmt.Sprintf("%d", len(tokenString))))

		// Validate token
		claims, err := am.validateToken(ctx, tokenString)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "token validation failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Set user context
		am.setUserContext(c, claims)
		
		span.SetAttributes(
			attribute.String("jwt.user_id", claims.RegisteredClaims.Subject),
			attribute.String("jwt.username", claims.PreferredUsername),
			attribute.String("jwt.client_id", claims.ClientID),
			attribute.StringSlice("jwt.roles", claims.RealmAccess.Roles),
		)
		span.SetStatus(codes.Ok, "token validated successfully")

		// Continue to next handler
		c.Next()
	}
}

// RequireRole middleware that checks for specific roles
func (am *AuthMiddleware) RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, span := am.tracer.Start(c.Request.Context(), "jwt.check_roles",
			trace.WithAttributes(
				attribute.StringSlice("jwt.required_roles", requiredRoles),
			),
		)
		defer span.End()

		// Get user roles from context
		userRoles, exists := c.Get(RolesKey)
		if !exists {
			span.SetStatus(codes.Error, "no roles found in context")
			c.JSON(http.StatusForbidden, gin.H{"error": "No roles found"})
			c.Abort()
			return
		}

		roles, ok := userRoles.([]string)
		if !ok {
			span.SetStatus(codes.Error, "invalid roles format")
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid roles format"})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, requiredRole := range requiredRoles {
			for _, userRole := range roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			span.SetAttributes(
				attribute.StringSlice("jwt.user_roles", roles),
				attribute.Bool("jwt.role_check_passed", false),
			)
			span.SetStatus(codes.Error, "insufficient permissions")
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		span.SetAttributes(
			attribute.StringSlice("jwt.user_roles", roles),
			attribute.Bool("jwt.role_check_passed", true),
		)
		span.SetStatus(codes.Ok, "role check passed")

		c.Next()
	}
}

// validateToken validates the JWT token and returns claims
func (am *AuthMiddleware) validateToken(ctx context.Context, tokenString string) (*JWTClaims, error) {
	ctx, span := am.tracer.Start(ctx, "jwt.parse_and_validate")
	defer span.End()

	// Parse token without verification first to get the kid
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to parse token")
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get key ID from token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		span.SetStatus(codes.Error, "missing kid in token header")
		return nil, fmt.Errorf("missing kid in token header")
	}

	span.SetAttributes(attribute.String("jwt.kid", kid))

	// Get public key for verification
	publicKey, err := am.getPublicKey(ctx, kid)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get public key")
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse and validate token with public key
	parsedToken, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "token validation failed")
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !parsedToken.Valid {
		span.SetStatus(codes.Error, "invalid token")
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := parsedToken.Claims.(*JWTClaims)
	if !ok {
		span.SetStatus(codes.Error, "invalid claims format")
		return nil, fmt.Errorf("invalid claims format")
	}

	// Additional validation
	if err := am.validateClaims(ctx, claims); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "claims validation failed")
		return nil, fmt.Errorf("claims validation failed: %w", err)
	}

	span.SetStatus(codes.Ok, "token validated successfully")
	return claims, nil
}

// getPublicKey retrieves the public key for token verification
func (am *AuthMiddleware) getPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	ctx, span := am.tracer.Start(ctx, "jwt.get_public_key",
		trace.WithAttributes(
			attribute.String("jwt.kid", kid),
		),
	)
	defer span.End()

	// Check cache first
	if publicKey, exists := am.jwksCache[kid]; exists {
		span.SetAttributes(attribute.Bool("jwks.cache_hit", true))
		span.SetStatus(codes.Ok, "public key retrieved from cache")
		return publicKey, nil
	}

	span.SetAttributes(attribute.Bool("jwks.cache_hit", false))

	// Try to get JWKS from Redis cache
	jwksData, found, err := am.cacheClient.GetJWKS(ctx, am.config.Keycloak.Realm)
	if err == nil && found {
		if jwks, ok := jwksData.(*JWKS); ok {
			publicKey, err := am.extractPublicKey(jwks, kid)
			if err == nil {
				am.jwksCache[kid] = publicKey
				span.SetAttributes(attribute.Bool("jwks.redis_hit", true))
				span.SetStatus(codes.Ok, "public key retrieved from Redis")
				return publicKey, nil
			}
		}
	}

	span.SetAttributes(attribute.Bool("jwks.redis_hit", false))

	// Fetch JWKS from Keycloak
	jwks, err := am.fetchJWKS(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fetch JWKS")
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Cache JWKS in Redis
	if err := am.cacheClient.SetJWKS(ctx, am.config.Keycloak.Realm, jwks, 1*time.Hour); err != nil {
		span.AddEvent("failed to cache JWKS", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	// Extract public key
	publicKey, err := am.extractPublicKey(jwks, kid)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to extract public key")
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Cache in memory
	am.jwksCache[kid] = publicKey

	span.SetStatus(codes.Ok, "public key retrieved from Keycloak")
	return publicKey, nil
}

// fetchJWKS fetches the JSON Web Key Set from Keycloak
func (am *AuthMiddleware) fetchJWKS(ctx context.Context) (*JWKS, error) {
	ctx, span := am.tracer.Start(ctx, "jwt.fetch_jwks")
	defer span.End()

	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", 
		am.config.Keycloak.BaseURL, am.config.Keycloak.Realm)

	span.SetAttributes(attribute.String("jwks.url", jwksURL))

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create request")
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "request failed")
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to decode JWKS")
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	span.SetAttributes(attribute.Int("jwks.keys_count", len(jwks.Keys)))
	span.SetStatus(codes.Ok, "JWKS fetched successfully")

	return &jwks, nil
}

// extractPublicKey extracts the RSA public key from JWKS
func (am *AuthMiddleware) extractPublicKey(jwks *JWKS, kid string) (*rsa.PublicKey, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			return am.jwkToRSAPublicKey(&key)
		}
	}
	return nil, fmt.Errorf("key with kid %s not found", kid)
}

// jwkToRSAPublicKey converts JWK to RSA public key
func (am *AuthMiddleware) jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

// validateClaims performs additional validation on token claims
func (am *AuthMiddleware) validateClaims(ctx context.Context, claims *JWTClaims) error {
	span := trace.SpanFromContext(ctx)
	span.AddEvent("validating claims")

	now := time.Now()

	// Check expiration
	if claims.RegisteredClaims.ExpiresAt != nil && claims.RegisteredClaims.ExpiresAt.Time.Before(now) {
		span.SetStatus(codes.Error, "token expired")
		return fmt.Errorf("token expired")
	}

	// Check not before
	if claims.RegisteredClaims.NotBefore != nil && claims.RegisteredClaims.NotBefore.Time.After(now) {
		span.SetStatus(codes.Error, "token not yet valid")
		return fmt.Errorf("token not yet valid")
	}

	// Check issuer
	expectedIssuer := fmt.Sprintf("%s/realms/%s", am.config.Keycloak.BaseURL, am.config.Keycloak.Realm)
	if claims.RegisteredClaims.Issuer != expectedIssuer {
		span.SetStatus(codes.Error, "invalid issuer")
		return fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, claims.RegisteredClaims.Issuer)
	}

	span.SetStatus(codes.Ok, "claims validated successfully")
	return nil
}

// setUserContext sets user information in the Gin context
func (am *AuthMiddleware) setUserContext(c *gin.Context, claims *JWTClaims) {
	c.Set(UserIDKey, claims.RegisteredClaims.Subject)
	c.Set(UsernameKey, claims.PreferredUsername)
	c.Set(RolesKey, claims.RealmAccess.Roles)
	c.Set(ClientIDKey, claims.ClientID)
	c.Set(TokenClaimsKey, claims)
}

// GetUserID retrieves user ID from context
func GetUserID(c *gin.Context) (string, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return "", false
	}
	id, ok := userID.(string)
	return id, ok
}

// GetUsername retrieves username from context
func GetUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get(UsernameKey)
	if !exists {
		return "", false
	}
	name, ok := username.(string)
	return name, ok
}

// GetUserRoles retrieves user roles from context
func GetUserRoles(c *gin.Context) ([]string, bool) {
	roles, exists := c.Get(RolesKey)
	if !exists {
		return nil, false
	}
	userRoles, ok := roles.([]string)
	return userRoles, ok
}