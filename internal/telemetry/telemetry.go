package telemetry

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds OpenTelemetry configuration
type Config struct {
	ServiceName     string
	ServiceVersion  string
	Environment     string
	OTLPEndpoint    string
	SamplingRatio   float64
	EnableMetrics   bool
	EnableTracing   bool
}

// LoadConfigFromEnv loads OpenTelemetry configuration from environment variables
func LoadConfigFromEnv() *Config {
	config := &Config{
		ServiceName:     getEnvOrDefault("OTEL_SERVICE_NAME", "keycloak-wrapper"),
		ServiceVersion:  getEnvOrDefault("OTEL_SERVICE_VERSION", "1.0.0"),
		Environment:     getEnvOrDefault("ENVIRONMENT", "development"),
		OTLPEndpoint:    getEnvOrDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
		SamplingRatio:   getEnvFloatOrDefault("OTEL_SAMPLING_RATIO", 0.01),
		EnableMetrics:   getEnvBoolOrDefault("OTEL_ENABLE_METRICS", true),
		EnableTracing:   getEnvBoolOrDefault("OTEL_ENABLE_TRACING", true),
	}
	return config
}

// InitTracing initializes OpenTelemetry tracing with OTLP exporter
func InitTracing(ctx context.Context, config *Config) (func(context.Context) error, error) {
	if !config.EnableTracing {
		return func(context.Context) error { return nil }, nil
	}

	// Create resource with service attributes
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
			semconv.DeploymentEnvironment(config.Environment),
			attribute.String("service.instance.id", generateInstanceID()),
		),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithContainer(),
		resource.WithProcess(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	var tracerProvider *sdktrace.TracerProvider

	// Try to create OTLP exporter, but don't fail if collector is not available
	if config.OTLPEndpoint != "" {
		// Create gRPC connection to OTLP collector with shorter timeout
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		conn, err := grpc.DialContext(ctx, config.OTLPEndpoint,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			fmt.Printf("Warning: Failed to connect to OTLP collector at %s: %v\n", config.OTLPEndpoint, err)
			fmt.Println("Continuing without OTLP exporter. Traces will be processed but not exported.")
			
			// Create tracer provider without exporter
			tracerProvider = sdktrace.NewTracerProvider(
				sdktrace.WithResource(res),
				sdktrace.WithSampler(createSampler(config.SamplingRatio)),
			)
		} else {
			// Create OTLP trace exporter
			traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
			if err != nil {
				fmt.Printf("Warning: Failed to create trace exporter: %v\n", err)
				fmt.Println("Continuing without OTLP exporter.")
				
				// Create tracer provider without exporter
				tracerProvider = sdktrace.NewTracerProvider(
					sdktrace.WithResource(res),
					sdktrace.WithSampler(createSampler(config.SamplingRatio)),
				)
			} else {
				// Create batch span processor
				bsp := sdktrace.NewBatchSpanProcessor(traceExporter)

				// Create tracer provider with exporter
				tracerProvider = sdktrace.NewTracerProvider(
					sdktrace.WithResource(res),
					sdktrace.WithSpanProcessor(bsp),
					sdktrace.WithSampler(createSampler(config.SamplingRatio)),
				)
				fmt.Printf("Successfully connected to OTLP collector at %s\n", config.OTLPEndpoint)
			}
		}
	} else {
		// No OTLP endpoint configured, create tracer provider without exporter
		tracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSampler(createSampler(config.SamplingRatio)),
		)
		fmt.Println("No OTLP endpoint configured. Traces will be processed locally only.")
	}

	// Set global tracer provider
	otel.SetTracerProvider(tracerProvider)

	// Set global propagator for context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Return shutdown function
	return func(ctx context.Context) error {
		// Shutdown tracer provider to flush remaining spans
		if err := tracerProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
		return nil
	}, nil
}

// createSampler creates a sampler based on the sampling ratio
func createSampler(ratio float64) sdktrace.Sampler {
	if ratio <= 0 {
		return sdktrace.NeverSample()
	}
	if ratio >= 1.0 {
		return sdktrace.AlwaysSample()
	}
	
	// Use ParentBased sampler with TraceIDRatioBased for root spans
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}

// generateInstanceID generates a unique instance identifier
func generateInstanceID() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	
	pid := os.Getpid()
	timestamp := time.Now().Unix()
	
	return fmt.Sprintf("%s-%d-%d", hostname, pid, timestamp)
}

// Helper functions for environment variable parsing
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvFloatOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// GetTracer returns a tracer for the given name
func GetTracer(name string) trace.Tracer {
	return otel.Tracer(name)
}