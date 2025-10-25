package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all custom Prometheus metrics for the service
type Metrics struct {
	// HTTP/gRPC Request Metrics
	HTTPRequestsTotal     *prometheus.CounterVec
	HTTPRequestDuration   *prometheus.HistogramVec
	GRPCRequestsTotal     *prometheus.CounterVec
	GRPCRequestDuration   *prometheus.HistogramVec

	// Authentication Metrics
	JWTValidationTotal    *prometheus.CounterVec
	JWTValidationDuration *prometheus.HistogramVec
	JWKSCacheHits         *prometheus.CounterVec
	AuthFailuresTotal     *prometheus.CounterVec

	// Keycloak Client Metrics
	KeycloakRequestsTotal     *prometheus.CounterVec
	KeycloakRequestDuration   *prometheus.HistogramVec
	KeycloakErrorsTotal       *prometheus.CounterVec
	KeycloakAdminTokenRefresh *prometheus.CounterVec

	// Cache Metrics
	CacheOperationsTotal *prometheus.CounterVec
	CacheHitRatio        *prometheus.GaugeVec
	CacheDuration        *prometheus.HistogramVec

	// Business Logic Metrics
	UserOperationsTotal   *prometheus.CounterVec
	TokenOperationsTotal  *prometheus.CounterVec
	ActiveSessions        *prometheus.GaugeVec
	
	// System Metrics
	DatabaseConnections   *prometheus.GaugeVec
	MemoryUsage          *prometheus.GaugeVec
	GoroutineCount       *prometheus.GaugeVec
}

// NewMetrics creates and registers all custom Prometheus metrics
func NewMetrics() *Metrics {
	return &Metrics{
		// HTTP Request Metrics
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_http_requests_total",
				Help: "Total number of HTTP requests processed",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_service_http_request_duration_seconds",
				Help:    "Duration of HTTP requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),

		// gRPC Request Metrics
		GRPCRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_grpc_requests_total",
				Help: "Total number of gRPC requests processed",
			},
			[]string{"method", "status_code"},
		),
		GRPCRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_service_grpc_request_duration_seconds",
				Help:    "Duration of gRPC requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),

		// JWT Authentication Metrics
		JWTValidationTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_jwt_validation_total",
				Help: "Total number of JWT validation attempts",
			},
			[]string{"result", "reason"},
		),
		JWTValidationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_service_jwt_validation_duration_seconds",
				Help:    "Duration of JWT validation in seconds",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
			},
			[]string{"result"},
		),
		JWKSCacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_jwks_cache_hits_total",
				Help: "Total number of JWKS cache hits/misses",
			},
			[]string{"cache_type", "result"},
		),
		AuthFailuresTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_auth_failures_total",
				Help: "Total number of authentication failures",
			},
			[]string{"reason", "endpoint"},
		),

		// Keycloak Client Metrics
		KeycloakRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_keycloak_requests_total",
				Help: "Total number of requests to Keycloak",
			},
			[]string{"operation", "status_code"},
		),
		KeycloakRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_service_keycloak_request_duration_seconds",
				Help:    "Duration of Keycloak requests in seconds",
				Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
			},
			[]string{"operation"},
		),
		KeycloakErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_keycloak_errors_total",
				Help: "Total number of Keycloak operation errors",
			},
			[]string{"operation", "error_type"},
		),
		KeycloakAdminTokenRefresh: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_keycloak_admin_token_refresh_total",
				Help: "Total number of Keycloak admin token refresh attempts",
			},
			[]string{"result"},
		),

		// Cache Metrics
		CacheOperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_cache_operations_total",
				Help: "Total number of cache operations",
			},
			[]string{"operation", "cache_type", "result"},
		),
		CacheHitRatio: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "auth_service_cache_hit_ratio",
				Help: "Cache hit ratio (0-1)",
			},
			[]string{"cache_type"},
		),
		CacheDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_service_cache_operation_duration_seconds",
				Help:    "Duration of cache operations in seconds",
				Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
			},
			[]string{"operation", "cache_type"},
		),

		// Business Logic Metrics
		UserOperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_user_operations_total",
				Help: "Total number of user operations",
			},
			[]string{"operation", "result"},
		),
		TokenOperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_service_token_operations_total",
				Help: "Total number of token operations",
			},
			[]string{"operation", "result"},
		),
		ActiveSessions: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "auth_service_active_sessions",
				Help: "Number of active user sessions",
			},
			[]string{"session_type"},
		),

		// System Metrics
		DatabaseConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "auth_service_database_connections",
				Help: "Number of active database connections",
			},
			[]string{"database", "state"},
		),
		MemoryUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "auth_service_memory_usage_bytes",
				Help: "Memory usage in bytes",
			},
			[]string{"type"},
		),
		GoroutineCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "auth_service_goroutines",
				Help: "Number of goroutines",
			},
			[]string{},
		),
	}
}

// RecordHTTPRequest records HTTP request metrics
func (m *Metrics) RecordHTTPRequest(method, endpoint, statusCode string, duration time.Duration) {
	m.HTTPRequestsTotal.WithLabelValues(method, endpoint, statusCode).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordGRPCRequest records gRPC request metrics
func (m *Metrics) RecordGRPCRequest(method, statusCode string, duration time.Duration) {
	m.GRPCRequestsTotal.WithLabelValues(method, statusCode).Inc()
	m.GRPCRequestDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordJWTValidation records JWT validation metrics
func (m *Metrics) RecordJWTValidation(result, reason string, duration time.Duration) {
	m.JWTValidationTotal.WithLabelValues(result, reason).Inc()
	m.JWTValidationDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// RecordJWKSCacheHit records JWKS cache hit/miss
func (m *Metrics) RecordJWKSCacheHit(cacheType, result string) {
	m.JWKSCacheHits.WithLabelValues(cacheType, result).Inc()
}

// RecordAuthFailure records authentication failure
func (m *Metrics) RecordAuthFailure(reason, endpoint string) {
	m.AuthFailuresTotal.WithLabelValues(reason, endpoint).Inc()
}

// RecordKeycloakRequest records Keycloak request metrics
func (m *Metrics) RecordKeycloakRequest(operation, statusCode string, duration time.Duration) {
	m.KeycloakRequestsTotal.WithLabelValues(operation, statusCode).Inc()
	m.KeycloakRequestDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordKeycloakError records Keycloak operation error
func (m *Metrics) RecordKeycloakError(operation, errorType string) {
	m.KeycloakErrorsTotal.WithLabelValues(operation, errorType).Inc()
}

// RecordKeycloakAdminTokenRefresh records admin token refresh
func (m *Metrics) RecordKeycloakAdminTokenRefresh(result string) {
	m.KeycloakAdminTokenRefresh.WithLabelValues(result).Inc()
}

// RecordCacheOperation records cache operation metrics
func (m *Metrics) RecordCacheOperation(operation, cacheType, result string, duration time.Duration) {
	m.CacheOperationsTotal.WithLabelValues(operation, cacheType, result).Inc()
	m.CacheDuration.WithLabelValues(operation, cacheType).Observe(duration.Seconds())
}

// UpdateCacheHitRatio updates cache hit ratio
func (m *Metrics) UpdateCacheHitRatio(cacheType string, ratio float64) {
	m.CacheHitRatio.WithLabelValues(cacheType).Set(ratio)
}

// RecordUserOperation records user operation metrics
func (m *Metrics) RecordUserOperation(operation, result string) {
	m.UserOperationsTotal.WithLabelValues(operation, result).Inc()
}

// RecordTokenOperation records token operation metrics
func (m *Metrics) RecordTokenOperation(operation, result string) {
	m.TokenOperationsTotal.WithLabelValues(operation, result).Inc()
}

// UpdateActiveSessions updates active sessions count
func (m *Metrics) UpdateActiveSessions(sessionType string, count float64) {
	m.ActiveSessions.WithLabelValues(sessionType).Set(count)
}

// UpdateSystemMetrics updates system-level metrics
func (m *Metrics) UpdateSystemMetrics(goroutines int, memoryUsage map[string]float64) {
	m.GoroutineCount.WithLabelValues().Set(float64(goroutines))
	
	for memType, usage := range memoryUsage {
		m.MemoryUsage.WithLabelValues(memType).Set(usage)
	}
}

// UpdateDatabaseConnections updates database connection metrics
func (m *Metrics) UpdateDatabaseConnections(database, state string, count float64) {
	m.DatabaseConnections.WithLabelValues(database, state).Set(count)
}