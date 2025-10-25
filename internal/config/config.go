package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// Config holds all application configuration
type Config struct {
	// Service configuration
	Service ServiceConfig `mapstructure:"service"`
	
	// Keycloak configuration
	Keycloak KeycloakConfig `mapstructure:"keycloak"`
	
	// Redis configuration
	Redis RedisConfig `mapstructure:"redis"`
	
	// OpenTelemetry configuration
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	
	// Server configuration
	Server ServerConfig `mapstructure:"server"`
	
	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics"`
}

// ServiceConfig holds service-level configuration
type ServiceConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Environment string `mapstructure:"environment"`
	LogLevel    string `mapstructure:"log_level"`
}

// KeycloakConfig holds Keycloak connection settings
type KeycloakConfig struct {
	BaseURL       string `mapstructure:"base_url"`
	Realm         string `mapstructure:"realm"`
	ClientID      string `mapstructure:"client_id"`
	ClientSecret  string `mapstructure:"client_secret"`
	AdminUsername string `mapstructure:"admin_username"`
	AdminPassword string `mapstructure:"admin_password"`
	Timeout       int    `mapstructure:"timeout"`
}

// RedisConfig holds Redis connection settings
type RedisConfig struct {
	URL      string `mapstructure:"url"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	Timeout  int    `mapstructure:"timeout"`
}

// TelemetryConfig holds OpenTelemetry settings
type TelemetryConfig struct {
	Enabled         bool    `mapstructure:"enabled"`
	OTLPEndpoint    string  `mapstructure:"otlp_endpoint"`
	SamplingRatio   float64 `mapstructure:"sampling_ratio"`
	EnableMetrics   bool    `mapstructure:"enable_metrics"`
	EnableTracing   bool    `mapstructure:"enable_tracing"`
	ResourceAttrs   string  `mapstructure:"resource_attributes"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	GRPCPort int `mapstructure:"grpc_port"`
	HTTPPort int `mapstructure:"http_port"`
}

// MetricsConfig holds metrics server configuration
type MetricsConfig struct {
	Port int    `mapstructure:"port"`
	Path string `mapstructure:"path"`
}

// Load loads configuration from environment variables and config files
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// .env file is optional, so we don't fail if it doesn't exist
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load .env file: %w", err)
		}
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/etc/auth-service")

	// Set default values
	setDefaults()

	// Enable environment variable binding
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Override with environment variables
	bindEnvVars()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Service defaults
	viper.SetDefault("service.name", "auth-service")
	viper.SetDefault("service.version", "1.0.0")
	viper.SetDefault("service.environment", "development")
	viper.SetDefault("service.log_level", "info")

	// Keycloak defaults
	viper.SetDefault("keycloak.base_url", "http://localhost:8090")
	viper.SetDefault("keycloak.realm", "master")
	viper.SetDefault("keycloak.client_id", "auth-service")
	viper.SetDefault("keycloak.timeout", 30)

	// Redis defaults
	viper.SetDefault("redis.url", "redis://localhost:6379/0")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.timeout", 5)

	// Telemetry defaults
	viper.SetDefault("telemetry.enabled", true)
	viper.SetDefault("telemetry.otlp_endpoint", "http://localhost:4317")
	viper.SetDefault("telemetry.sampling_ratio", 0.01)
	viper.SetDefault("telemetry.enable_metrics", true)
	viper.SetDefault("telemetry.enable_tracing", true)

	// Server defaults
	viper.SetDefault("server.grpc_port", 8081)
	viper.SetDefault("server.http_port", 8080)

	// Metrics defaults
	viper.SetDefault("metrics.port", 9091)
	viper.SetDefault("metrics.path", "/metrics")
}

// bindEnvVars binds environment variables to configuration keys
func bindEnvVars() {
	// Service
	viper.BindEnv("service.name", "SERVICE_NAME")
	viper.BindEnv("service.version", "SERVICE_VERSION")
	viper.BindEnv("service.environment", "ENVIRONMENT")
	viper.BindEnv("service.log_level", "LOG_LEVEL")

	// Keycloak
	viper.BindEnv("keycloak.base_url", "KEYCLOAK_BASE_URL")
	viper.BindEnv("keycloak.realm", "KEYCLOAK_REALM")
	viper.BindEnv("keycloak.client_id", "KEYCLOAK_CLIENT_ID")
	viper.BindEnv("keycloak.client_secret", "KEYCLOAK_CLIENT_SECRET")
	viper.BindEnv("keycloak.admin_username", "KEYCLOAK_ADMIN_USERNAME")
	viper.BindEnv("keycloak.admin_password", "KEYCLOAK_ADMIN_PASSWORD")

	// Redis
	viper.BindEnv("redis.url", "REDIS_URL")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("redis.db", "REDIS_DB")

	// Telemetry
	viper.BindEnv("telemetry.otlp_endpoint", "OTEL_EXPORTER_OTLP_ENDPOINT")
	viper.BindEnv("telemetry.sampling_ratio", "OTEL_SAMPLING_RATIO")
	viper.BindEnv("telemetry.resource_attributes", "OTEL_RESOURCE_ATTRIBUTES")

	// Server
	viper.BindEnv("server.grpc_port", "GRPC_PORT")
	viper.BindEnv("server.http_port", "HTTP_PORT")

	// Metrics
	viper.BindEnv("metrics.port", "METRICS_PORT")
	viper.BindEnv("metrics.path", "METRICS_PATH")
}

// validate validates the configuration
func validate(config *Config) error {
	if config.Service.Name == "" {
		return fmt.Errorf("service name is required")
	}

	if config.Keycloak.BaseURL == "" {
		return fmt.Errorf("keycloak base URL is required")
	}

	if config.Keycloak.Realm == "" {
		return fmt.Errorf("keycloak realm is required")
	}

	if config.Redis.URL == "" {
		return fmt.Errorf("redis URL is required")
	}

	if config.Server.GRPCPort <= 0 || config.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", config.Server.GRPCPort)
	}

	if config.Server.HTTPPort <= 0 || config.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", config.Server.HTTPPort)
	}

	if config.Telemetry.SamplingRatio < 0 || config.Telemetry.SamplingRatio > 1 {
		return fmt.Errorf("invalid sampling ratio: %f", config.Telemetry.SamplingRatio)
	}

	return nil
}

// GetEnvOrDefault returns environment variable value or default
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvIntOrDefault returns environment variable as int or default
func GetEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// GetEnvBoolOrDefault returns environment variable as bool or default
func GetEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}