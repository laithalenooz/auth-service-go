package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/laithalenooz/auth-service-go/internal/metrics"
)

const metricsTracerName = "metrics-middleware"

// MetricsMiddleware provides HTTP request metrics collection
type MetricsMiddleware struct {
	metrics *metrics.Metrics
	tracer  trace.Tracer
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware(m *metrics.Metrics) *MetricsMiddleware {
	return &MetricsMiddleware{
		metrics: m,
		tracer:  otel.Tracer(metricsTracerName),
	}
}

// HTTPMetrics returns a Gin middleware that collects HTTP request metrics
func (mm *MetricsMiddleware) HTTPMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Start tracing span for metrics collection
		ctx, span := mm.tracer.Start(c.Request.Context(), "http.metrics",
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.route", c.FullPath()),
			),
		)
		defer span.End()
		
		// Update context
		c.Request = c.Request.WithContext(ctx)
		
		// Process request
		c.Next()
		
		// Calculate duration
		duration := time.Since(start)
		
		// Get response status
		statusCode := strconv.Itoa(c.Writer.Status())
		
		// Record metrics
		mm.metrics.RecordHTTPRequest(
			c.Request.Method,
			c.FullPath(),
			statusCode,
			duration,
		)
		
		// Add span attributes
		span.SetAttributes(
			attribute.String("http.status_code", statusCode),
			attribute.Float64("http.duration_seconds", duration.Seconds()),
			attribute.Int("http.response_size", c.Writer.Size()),
		)
		
		// Record authentication failures if applicable
		if c.Writer.Status() == 401 {
			mm.metrics.RecordAuthFailure("unauthorized", c.FullPath())
		} else if c.Writer.Status() == 403 {
			mm.metrics.RecordAuthFailure("forbidden", c.FullPath())
		}
	}
}

// ErrorMetrics returns a Gin middleware that tracks error metrics
func (mm *MetricsMiddleware) ErrorMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		
		// Check for errors
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				// Categorize error types
				errorType := "unknown"
				switch err.Type {
				case gin.ErrorTypeBind:
					errorType = "validation"
				case gin.ErrorTypePublic:
					errorType = "client"
				case gin.ErrorTypePrivate:
					errorType = "server"
				case gin.ErrorTypeRender:
					errorType = "render"
				}
				
				// Record authentication-specific errors
				if c.Writer.Status() >= 400 && c.Writer.Status() < 500 {
					mm.metrics.RecordAuthFailure(errorType, c.FullPath())
				}
			}
		}
	}
}

// BusinessLogicMetrics provides methods to record business logic metrics
func (mm *MetricsMiddleware) BusinessLogicMetrics() *BusinessMetrics {
	return &BusinessMetrics{
		metrics: mm.metrics,
		tracer:  mm.tracer,
	}
}

// BusinessMetrics provides business logic metric recording
type BusinessMetrics struct {
	metrics *metrics.Metrics
	tracer  trace.Tracer
}

// RecordUserOperation records user-related operations
func (bm *BusinessMetrics) RecordUserOperation(operation, result string) {
	bm.metrics.RecordUserOperation(operation, result)
}

// RecordTokenOperation records token-related operations
func (bm *BusinessMetrics) RecordTokenOperation(operation, result string) {
	bm.metrics.RecordTokenOperation(operation, result)
}

// RecordJWTValidation records JWT validation with tracing
func (bm *BusinessMetrics) RecordJWTValidation(result, reason string, duration time.Duration) {
	bm.metrics.RecordJWTValidation(result, reason, duration)
}

// RecordJWKSCacheHit records JWKS cache performance
func (bm *BusinessMetrics) RecordJWKSCacheHit(cacheType, result string) {
	bm.metrics.RecordJWKSCacheHit(cacheType, result)
}

// RecordKeycloakOperation records Keycloak client operations
func (bm *BusinessMetrics) RecordKeycloakOperation(operation, statusCode string, duration time.Duration) {
	bm.metrics.RecordKeycloakRequest(operation, statusCode, duration)
}

// RecordKeycloakError records Keycloak operation errors
func (bm *BusinessMetrics) RecordKeycloakError(operation, errorType string) {
	bm.metrics.RecordKeycloakError(operation, errorType)
}

// RecordCacheOperation records cache operations
func (bm *BusinessMetrics) RecordCacheOperation(operation, cacheType, result string, duration time.Duration) {
	bm.metrics.RecordCacheOperation(operation, cacheType, result, duration)
}

// UpdateCacheHitRatio updates cache hit ratio metrics
func (bm *BusinessMetrics) UpdateCacheHitRatio(cacheType string, ratio float64) {
	bm.metrics.UpdateCacheHitRatio(cacheType, ratio)
}