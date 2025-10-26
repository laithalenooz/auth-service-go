package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/laithalenooz/auth-service-go/internal/cache"
	"github.com/laithalenooz/auth-service-go/internal/config"
	"github.com/laithalenooz/auth-service-go/internal/keycloak"
	"github.com/laithalenooz/auth-service-go/internal/metrics"
)

const tracerName = "health-checker"

// Status represents the health status of a component
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Status      Status            `json:"status"`
	Message     string            `json:"message,omitempty"`
	LastChecked time.Time         `json:"last_checked"`
	Duration    time.Duration     `json:"duration"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// OverallHealth represents the overall health of the service
type OverallHealth struct {
	Status       Status                      `json:"status"`
	Timestamp    time.Time                   `json:"timestamp"`
	Version      string                      `json:"version"`
	Uptime       time.Duration               `json:"uptime"`
	Dependencies map[string]*ComponentHealth `json:"dependencies"`
}

// Checker defines the interface for health checkers
type Checker interface {
	Check(ctx context.Context) *ComponentHealth
	Name() string
}

// HealthService manages health checks for all dependencies
type HealthService struct {
	config      *config.Config
	checkers    map[string]Checker
	cache       map[string]*ComponentHealth
	cacheMutex  sync.RWMutex
	metrics     *metrics.Metrics
	tracer      trace.Tracer
	startTime   time.Time
	lastCheck   time.Time
	checkMutex  sync.Mutex
}

// NewHealthService creates a new health service
func NewHealthService(cfg *config.Config, m *metrics.Metrics) *HealthService {
	return &HealthService{
		config:    cfg,
		checkers:  make(map[string]Checker),
		cache:     make(map[string]*ComponentHealth),
		metrics:   m,
		tracer:    otel.Tracer(tracerName),
		startTime: time.Now(),
	}
}

// RegisterChecker registers a health checker
func (hs *HealthService) RegisterChecker(checker Checker) {
	hs.checkers[checker.Name()] = checker
}

// CheckAll performs health checks on all registered components
func (hs *HealthService) CheckAll(ctx context.Context) *OverallHealth {
	hs.checkMutex.Lock()
	defer hs.checkMutex.Unlock()

	ctx, span := hs.tracer.Start(ctx, "health.check_all",
		trace.WithAttributes(
			attribute.Int("health.checkers_count", len(hs.checkers)),
		),
	)
	defer span.End()

	start := time.Now()
	dependencies := make(map[string]*ComponentHealth)
	overallStatus := StatusHealthy

	// Run health checks concurrently
	var wg sync.WaitGroup
	resultChan := make(chan struct {
		name   string
		health *ComponentHealth
	}, len(hs.checkers))

	for name, checker := range hs.checkers {
		wg.Add(1)
		go func(name string, checker Checker) {
			defer wg.Done()
			health := checker.Check(ctx)
			resultChan <- struct {
				name   string
				health *ComponentHealth
			}{name, health}
		}(name, checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		dependencies[result.name] = result.health
		
		// Update cache
		hs.cacheMutex.Lock()
		hs.cache[result.name] = result.health
		hs.cacheMutex.Unlock()

		// Update metrics
		hs.updateHealthMetrics(result.name, result.health)

		// Determine overall status
		switch result.health.Status {
		case StatusUnhealthy:
			overallStatus = StatusUnhealthy
		case StatusDegraded:
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		}
	}

	duration := time.Since(start)
	hs.lastCheck = time.Now()

	// Update overall health metrics
	hs.metrics.UpdateSystemMetrics(0, map[string]float64{
		"health_check_duration": duration.Seconds(),
	})

	span.SetAttributes(
		attribute.String("health.overall_status", string(overallStatus)),
		attribute.Float64("health.check_duration_seconds", duration.Seconds()),
	)
	span.SetStatus(codes.Ok, "health check completed")

	return &OverallHealth{
		Status:       overallStatus,
		Timestamp:    time.Now(),
		Version:      hs.config.Service.Version,
		Uptime:       time.Since(hs.startTime),
		Dependencies: dependencies,
	}
}

// GetCachedHealth returns cached health status for quick responses
func (hs *HealthService) GetCachedHealth() *OverallHealth {
	hs.cacheMutex.RLock()
	defer hs.cacheMutex.RUnlock()

	dependencies := make(map[string]*ComponentHealth)
	overallStatus := StatusHealthy

	for name, health := range hs.cache {
		dependencies[name] = health
		switch health.Status {
		case StatusUnhealthy:
			overallStatus = StatusUnhealthy
		case StatusDegraded:
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		}
	}

	return &OverallHealth{
		Status:       overallStatus,
		Timestamp:    hs.lastCheck,
		Version:      hs.config.Service.Version,
		Uptime:       time.Since(hs.startTime),
		Dependencies: dependencies,
	}
}

// updateHealthMetrics updates Prometheus metrics based on health check results
func (hs *HealthService) updateHealthMetrics(componentName string, health *ComponentHealth) {
	// Update dependency health metrics
	var statusValue float64
	switch health.Status {
	case StatusHealthy:
		statusValue = 1
	case StatusDegraded:
		statusValue = 0.5
	case StatusUnhealthy:
		statusValue = 0
	default:
		statusValue = -1
	}

	hs.metrics.UpdateDatabaseConnections(componentName, "health_status", statusValue)
}

// RedisHealthChecker checks Redis connectivity and performance
type RedisHealthChecker struct {
	client  *cache.Client
	tracer  trace.Tracer
	metrics *metrics.Metrics
}

// NewRedisHealthChecker creates a new Redis health checker
func NewRedisHealthChecker(client *cache.Client, m *metrics.Metrics) *RedisHealthChecker {
	return &RedisHealthChecker{
		client:  client,
		tracer:  otel.Tracer(tracerName),
		metrics: m,
	}
}

// Name returns the checker name
func (r *RedisHealthChecker) Name() string {
	return "redis"
}

// Check performs Redis health check
func (r *RedisHealthChecker) Check(ctx context.Context) *ComponentHealth {
	start := time.Now()
	ctx, span := r.tracer.Start(ctx, "health.redis.check")
	defer span.End()

	health := &ComponentHealth{
		LastChecked: time.Now(),
		Metadata:    make(map[string]string),
	}

	// Test basic connectivity with ping
	if err := r.client.Ping(ctx); err != nil {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("Redis ping failed: %v", err)
		health.Duration = time.Since(start)
		
		span.RecordError(err)
		span.SetStatus(codes.Error, "Redis ping failed")
		r.metrics.RecordCacheOperation("ping", "redis", "failure", health.Duration)
		return health
	}

	// Test set/get operations using admin token cache methods
	testValue := fmt.Sprintf("health_test_%d", time.Now().Unix())
	
	if err := r.client.SetAdminToken(ctx, testValue, time.Minute); err != nil {
		health.Status = StatusDegraded
		health.Message = fmt.Sprintf("Redis set operation failed: %v", err)
		health.Duration = time.Since(start)
		
		span.RecordError(err)
		span.SetStatus(codes.Error, "Redis set failed")
		r.metrics.RecordCacheOperation("set", "redis", "failure", health.Duration)
		return health
	}

	retrievedValue, found, err := r.client.GetAdminToken(ctx)
	if err != nil {
		health.Status = StatusDegraded
		health.Message = fmt.Sprintf("Redis get operation failed: %v", err)
		health.Duration = time.Since(start)
		
		span.RecordError(err)
		span.SetStatus(codes.Error, "Redis get failed")
		r.metrics.RecordCacheOperation("get", "redis", "failure", health.Duration)
		return health
	}

	if !found {
		health.Status = StatusDegraded
		health.Message = "Redis data not found after set operation"
		health.Duration = time.Since(start)
		
		span.SetStatus(codes.Error, "Redis data not found")
		return health
	}

	if retrievedValue != testValue {
		health.Status = StatusDegraded
		health.Message = "Redis data integrity check failed"
		health.Duration = time.Since(start)
		
		span.SetStatus(codes.Error, "Redis data integrity failed")
		return health
	}

	health.Status = StatusHealthy
	health.Message = "Redis is healthy"
	health.Duration = time.Since(start)
	health.Metadata["ping_duration"] = health.Duration.String()

	span.SetStatus(codes.Ok, "Redis health check passed")
	r.metrics.RecordCacheOperation("health_check", "redis", "success", health.Duration)

	return health
}

// KeycloakHealthChecker checks Keycloak connectivity and admin token validity
type KeycloakHealthChecker struct {
	client  *keycloak.Client
	config  *config.KeycloakConfig
	tracer  trace.Tracer
	metrics *metrics.Metrics
}

// NewKeycloakHealthChecker creates a new Keycloak health checker
func NewKeycloakHealthChecker(client *keycloak.Client, cfg *config.KeycloakConfig, m *metrics.Metrics) *KeycloakHealthChecker {
	return &KeycloakHealthChecker{
		client:  client,
		config:  cfg,
		tracer:  otel.Tracer(tracerName),
		metrics: m,
	}
}

// Name returns the checker name
func (k *KeycloakHealthChecker) Name() string {
	return "keycloak"
}

// Check performs Keycloak health check
func (k *KeycloakHealthChecker) Check(ctx context.Context) *ComponentHealth {
	start := time.Now()
	ctx, span := k.tracer.Start(ctx, "health.keycloak.check")
	defer span.End()

	health := &ComponentHealth{
		LastChecked: time.Now(),
		Metadata:    make(map[string]string),
	}

	// Test a simple API call (get users count with limit 1)
	// This will internally ensure admin token is valid
	// Use config values for health check
	_, _, err := k.client.ListUsers(ctx, k.config.Realm, k.config.ClientID, k.config.ClientSecret, 0, 1, "", "", "")
	if err != nil {
		health.Status = StatusUnhealthy
		health.Message = fmt.Sprintf("Keycloak API test failed: %v", err)
		health.Duration = time.Since(start)
		
		span.RecordError(err)
		span.SetStatus(codes.Error, "Keycloak API test failed")
		k.metrics.RecordKeycloakError("health_check", "api_error")
		return health
	}

	health.Status = StatusHealthy
	health.Message = "Keycloak is healthy"
	health.Duration = time.Since(start)
	health.Metadata["api_duration"] = health.Duration.String()

	span.SetStatus(codes.Ok, "Keycloak health check passed")
	k.metrics.RecordKeycloakRequest("health_check", "200", health.Duration)

	return health
}

// StartPeriodicHealthChecks starts background health checking
func (hs *HealthService) StartPeriodicHealthChecks(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Perform health checks in background
			go func() {
				checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				hs.CheckAll(checkCtx)
			}()
		}
	}
}