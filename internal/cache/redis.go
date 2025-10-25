package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/extra/redisotel/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"github.com/laithalenooz/auth-service-go/internal/config"
)

const (
	tracerName = "redis-cache"
	
	// Cache key prefixes
	AdminTokenPrefix = "keycloak:admin:token"
	JWKSPrefix      = "keycloak:jwks"
	UserCachePrefix = "keycloak:user"
	TokenCachePrefix = "keycloak:token"
)

// Client represents an instrumented Redis client
type Client struct {
	rdb    redis.UniversalClient
	tracer trace.Tracer
	config *config.RedisConfig
}

// CacheItem represents a cached item with metadata
type CacheItem struct {
	Data      interface{} `json:"data"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

// NewClient creates a new instrumented Redis client
func NewClient(cfg *config.RedisConfig) (*Client, error) {
	// Parse Redis URL
	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Override with config values
	if cfg.Password != "" {
		opt.Password = cfg.Password
	}
	opt.DB = cfg.DB

	// Create Redis client
	rdb := redis.NewClient(opt)

	// Enable OpenTelemetry tracing instrumentation
	if err := redisotel.InstrumentTracing(rdb,
		redisotel.WithAttributes(
			attribute.String("db.system", "redis"),
			attribute.String("db.redis.database_index", fmt.Sprintf("%d", cfg.DB)),
		),
	); err != nil {
		return nil, fmt.Errorf("failed to instrument Redis tracing: %w", err)
	}

	// Enable OpenTelemetry metrics instrumentation
	if err := redisotel.InstrumentMetrics(rdb); err != nil {
		return nil, fmt.Errorf("failed to instrument Redis metrics: %w", err)
	}

	client := &Client{
		rdb:    rdb,
		tracer: otel.Tracer(tracerName),
		config: cfg,
	}

	return client, nil
}

// Ping tests the Redis connection
func (c *Client) Ping(ctx context.Context) error {
	ctx, span := c.tracer.Start(ctx, "redis.ping")
	defer span.End()

	result := c.rdb.Ping(ctx)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "ping failed")
		return fmt.Errorf("redis ping failed: %w", err)
	}

	span.SetStatus(codes.Ok, "ping successful")
	return nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.rdb.Close()
}

// SetAdminToken caches the admin token
func (c *Client) SetAdminToken(ctx context.Context, token interface{}, ttl time.Duration) error {
	ctx, span := c.tracer.Start(ctx, "redis.set_admin_token",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", AdminTokenPrefix),
			attribute.String("cache.operation", "set"),
			attribute.String("cache.ttl", ttl.String()),
		),
	)
	defer span.End()

	key := AdminTokenPrefix
	
	item := CacheItem{
		Data:      token,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(item)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal token")
		return fmt.Errorf("failed to marshal admin token: %w", err)
	}

	result := c.rdb.Set(ctx, key, data, ttl)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to set admin token")
		return fmt.Errorf("failed to cache admin token: %w", err)
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", false),
	)
	span.SetStatus(codes.Ok, "admin token cached")

	return nil
}

// GetAdminToken retrieves the cached admin token
func (c *Client) GetAdminToken(ctx context.Context) (interface{}, bool, error) {
	ctx, span := c.tracer.Start(ctx, "redis.get_admin_token",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", AdminTokenPrefix),
			attribute.String("cache.operation", "get"),
		),
	)
	defer span.End()

	key := AdminTokenPrefix

	result := c.rdb.Get(ctx, key)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			span.SetAttributes(
				attribute.String("cache.key", key),
				attribute.Bool("cache.hit", false),
			)
			span.SetStatus(codes.Ok, "admin token not found")
			return nil, false, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get admin token")
		return nil, false, fmt.Errorf("failed to get admin token: %w", err)
	}

	var item CacheItem
	if err := json.Unmarshal([]byte(result.Val()), &item); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to unmarshal token")
		return nil, false, fmt.Errorf("failed to unmarshal admin token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(item.ExpiresAt) {
		span.SetAttributes(
			attribute.String("cache.key", key),
			attribute.Bool("cache.hit", false),
			attribute.Bool("cache.expired", true),
		)
		span.SetStatus(codes.Ok, "admin token expired")
		return nil, false, nil
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", true),
		attribute.String("cache.created_at", item.CreatedAt.Format(time.RFC3339)),
		attribute.String("cache.expires_at", item.ExpiresAt.Format(time.RFC3339)),
	)
	span.SetStatus(codes.Ok, "admin token retrieved")

	return item.Data, true, nil
}

// SetJWKS caches the JWKS (JSON Web Key Set)
func (c *Client) SetJWKS(ctx context.Context, realm string, jwks interface{}, ttl time.Duration) error {
	ctx, span := c.tracer.Start(ctx, "redis.set_jwks",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", JWKSPrefix),
			attribute.String("cache.operation", "set"),
			attribute.String("keycloak.realm", realm),
			attribute.String("cache.ttl", ttl.String()),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:%s", JWKSPrefix, realm)
	
	item := CacheItem{
		Data:      jwks,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(item)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal JWKS")
		return fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	result := c.rdb.Set(ctx, key, data, ttl)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to set JWKS")
		return fmt.Errorf("failed to cache JWKS: %w", err)
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", false),
	)
	span.SetStatus(codes.Ok, "JWKS cached")

	return nil
}

// GetJWKS retrieves the cached JWKS
func (c *Client) GetJWKS(ctx context.Context, realm string) (interface{}, bool, error) {
	ctx, span := c.tracer.Start(ctx, "redis.get_jwks",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", JWKSPrefix),
			attribute.String("cache.operation", "get"),
			attribute.String("keycloak.realm", realm),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:%s", JWKSPrefix, realm)

	result := c.rdb.Get(ctx, key)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			span.SetAttributes(
				attribute.String("cache.key", key),
				attribute.Bool("cache.hit", false),
			)
			span.SetStatus(codes.Ok, "JWKS not found")
			return nil, false, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get JWKS")
		return nil, false, fmt.Errorf("failed to get JWKS: %w", err)
	}

	var item CacheItem
	if err := json.Unmarshal([]byte(result.Val()), &item); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to unmarshal JWKS")
		return nil, false, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	// Check if JWKS is expired
	if time.Now().After(item.ExpiresAt) {
		span.SetAttributes(
			attribute.String("cache.key", key),
			attribute.Bool("cache.hit", false),
			attribute.Bool("cache.expired", true),
		)
		span.SetStatus(codes.Ok, "JWKS expired")
		return nil, false, nil
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", true),
		attribute.String("cache.created_at", item.CreatedAt.Format(time.RFC3339)),
		attribute.String("cache.expires_at", item.ExpiresAt.Format(time.RFC3339)),
	)
	span.SetStatus(codes.Ok, "JWKS retrieved")

	return item.Data, true, nil
}

// SetUser caches user data
func (c *Client) SetUser(ctx context.Context, userID string, user interface{}, ttl time.Duration) error {
	ctx, span := c.tracer.Start(ctx, "redis.set_user",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", UserCachePrefix),
			attribute.String("cache.operation", "set"),
			attribute.String("keycloak.user.id", userID),
			attribute.String("cache.ttl", ttl.String()),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:%s", UserCachePrefix, userID)
	
	item := CacheItem{
		Data:      user,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(item)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal user")
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	result := c.rdb.Set(ctx, key, data, ttl)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to set user")
		return fmt.Errorf("failed to cache user: %w", err)
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", false),
	)
	span.SetStatus(codes.Ok, "user cached")

	return nil
}

// GetUser retrieves cached user data
func (c *Client) GetUser(ctx context.Context, userID string) (interface{}, bool, error) {
	ctx, span := c.tracer.Start(ctx, "redis.get_user",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", UserCachePrefix),
			attribute.String("cache.operation", "get"),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:%s", UserCachePrefix, userID)

	result := c.rdb.Get(ctx, key)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			span.SetAttributes(
				attribute.String("cache.key", key),
				attribute.Bool("cache.hit", false),
			)
			span.SetStatus(codes.Ok, "user not found")
			return nil, false, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get user")
		return nil, false, fmt.Errorf("failed to get user: %w", err)
	}

	var item CacheItem
	if err := json.Unmarshal([]byte(result.Val()), &item); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to unmarshal user")
		return nil, false, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	// Check if user data is expired
	if time.Now().After(item.ExpiresAt) {
		span.SetAttributes(
			attribute.String("cache.key", key),
			attribute.Bool("cache.hit", false),
			attribute.Bool("cache.expired", true),
		)
		span.SetStatus(codes.Ok, "user data expired")
		return nil, false, nil
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", true),
		attribute.String("cache.created_at", item.CreatedAt.Format(time.RFC3339)),
		attribute.String("cache.expires_at", item.ExpiresAt.Format(time.RFC3339)),
	)
	span.SetStatus(codes.Ok, "user retrieved")

	return item.Data, true, nil
}

// DeleteUser removes user data from cache
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	ctx, span := c.tracer.Start(ctx, "redis.delete_user",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", UserCachePrefix),
			attribute.String("cache.operation", "delete"),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:%s", UserCachePrefix, userID)

	result := c.rdb.Del(ctx, key)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to delete user")
		return fmt.Errorf("failed to delete user from cache: %w", err)
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Int64("cache.deleted_count", result.Val()),
	)
	span.SetStatus(codes.Ok, "user deleted")

	return nil
}

// SetTokenIntrospection caches token introspection result
func (c *Client) SetTokenIntrospection(ctx context.Context, tokenHash string, introspection interface{}, ttl time.Duration) error {
	ctx, span := c.tracer.Start(ctx, "redis.set_token_introspection",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", TokenCachePrefix),
			attribute.String("cache.operation", "set"),
			attribute.String("cache.ttl", ttl.String()),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:introspect:%s", TokenCachePrefix, tokenHash)
	
	item := CacheItem{
		Data:      introspection,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(item)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal introspection")
		return fmt.Errorf("failed to marshal token introspection: %w", err)
	}

	result := c.rdb.Set(ctx, key, data, ttl)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to set introspection")
		return fmt.Errorf("failed to cache token introspection: %w", err)
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", false),
	)
	span.SetStatus(codes.Ok, "token introspection cached")

	return nil
}

// GetTokenIntrospection retrieves cached token introspection result
func (c *Client) GetTokenIntrospection(ctx context.Context, tokenHash string) (interface{}, bool, error) {
	ctx, span := c.tracer.Start(ctx, "redis.get_token_introspection",
		trace.WithAttributes(
			attribute.String("cache.key_prefix", TokenCachePrefix),
			attribute.String("cache.operation", "get"),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:introspect:%s", TokenCachePrefix, tokenHash)

	result := c.rdb.Get(ctx, key)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			span.SetAttributes(
				attribute.String("cache.key", key),
				attribute.Bool("cache.hit", false),
			)
			span.SetStatus(codes.Ok, "token introspection not found")
			return nil, false, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get introspection")
		return nil, false, fmt.Errorf("failed to get token introspection: %w", err)
	}

	var item CacheItem
	if err := json.Unmarshal([]byte(result.Val()), &item); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to unmarshal introspection")
		return nil, false, fmt.Errorf("failed to unmarshal token introspection: %w", err)
	}

	// Check if introspection is expired
	if time.Now().After(item.ExpiresAt) {
		span.SetAttributes(
			attribute.String("cache.key", key),
			attribute.Bool("cache.hit", false),
			attribute.Bool("cache.expired", true),
		)
		span.SetStatus(codes.Ok, "token introspection expired")
		return nil, false, nil
	}

	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Bool("cache.hit", true),
		attribute.String("cache.created_at", item.CreatedAt.Format(time.RFC3339)),
		attribute.String("cache.expires_at", item.ExpiresAt.Format(time.RFC3339)),
	)
	span.SetStatus(codes.Ok, "token introspection retrieved")

	return item.Data, true, nil
}