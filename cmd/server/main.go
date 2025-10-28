package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	keycloakv1 "github.com/laithalenooz/auth-service-go/gen/keycloak/v1"
	"github.com/laithalenooz/auth-service-go/internal/cache"
	"github.com/laithalenooz/auth-service-go/internal/config"
	"github.com/laithalenooz/auth-service-go/internal/health"
	"github.com/laithalenooz/auth-service-go/internal/keycloak"
	"github.com/laithalenooz/auth-service-go/internal/metrics"
	"github.com/laithalenooz/auth-service-go/internal/middleware"
	"github.com/laithalenooz/auth-service-go/internal/server"
	"github.com/laithalenooz/auth-service-go/internal/telemetry"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize OpenTelemetry
	ctx := context.Background()
	telemetryConfig := &telemetry.Config{
		ServiceName:    cfg.Service.Name,
		ServiceVersion: cfg.Service.Version,
		Environment:    cfg.Service.Environment,
		OTLPEndpoint:   cfg.Telemetry.OTLPEndpoint,
		SamplingRatio:  cfg.Telemetry.SamplingRatio,
		EnableMetrics:  cfg.Telemetry.EnableMetrics,
		EnableTracing:  cfg.Telemetry.EnableTracing,
	}

	shutdown, err := telemetry.InitTracing(ctx, telemetryConfig)
	if err != nil {
		log.Fatalf("Failed to initialize telemetry: %v", err)
	}
	defer func() {
		if shutdownErr := shutdown(ctx); shutdownErr != nil {
			log.Printf("Failed to shutdown telemetry: %v", shutdownErr)
		}
	}()

	// Initialize Redis cache
	cacheClient, err := cache.NewClient(&cfg.Redis)
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}
	defer cacheClient.Close()

	// Test Redis connection
	if err := cacheClient.Ping(ctx); err != nil {
		log.Printf("Warning: Redis connection failed: %v", err)
	} else {
		log.Println("Redis connection established")
	}

	// Initialize metrics (single instance for the entire application)
	appMetrics := metrics.NewMetrics()

	// Initialize Keycloak client
	keycloakClient := keycloak.NewClient(&cfg.Keycloak, appMetrics)

	// Initialize health service
	healthService := health.NewHealthService(cfg, appMetrics)
	healthService.RegisterChecker(health.NewRedisHealthChecker(cacheClient, appMetrics))
	healthService.RegisterChecker(health.NewKeycloakHealthChecker(keycloakClient, &cfg.Keycloak, appMetrics))

	// Start periodic health checks
	go healthService.StartPeriodicHealthChecks(context.Background(), 30*time.Second)

	// Create gRPC server
	grpcServer := server.NewGRPCServer(cfg, keycloakClient, cacheClient)

	// Start servers based on command line arguments
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "grpc":
			startGRPCServer(grpcServer, cfg.Server.GRPCPort)
		case "http":
			startHTTPServer(cfg, cfg.Server.HTTPPort, cfg.Server.GRPCPort, healthService, appMetrics)
		case "all":
			startBothServers(grpcServer, cfg, healthService, appMetrics)
		default:
			printUsage()
		}
	} else {
		startBothServers(grpcServer, cfg, healthService, appMetrics)
	}
}

func verifyTokenHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.VerifyTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		resp, err := client.VerifyToken(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func startGRPCServer(grpcServer *server.GRPCServer, port int) {
	log.Printf("Starting gRPC server on port %d", port)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpcServer.CreateServer()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down gRPC server...")
		s.GracefulStop()
	}()

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func startHTTPServer(cfg *config.Config, httpPort, grpcPort int, healthService *health.HealthService, appMetrics *metrics.Metrics) {
	log.Printf("Starting HTTP server on port %d (proxying to gRPC on port %d)", httpPort, grpcPort)

	// Create HTTP server with REST endpoints
	router := createHTTPRouter(cfg, grpcPort, healthService, appMetrics)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", httpPort),
		Handler: router,
	}

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down HTTP server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func startBothServers(grpcServer *server.GRPCServer, cfg *config.Config, healthService *health.HealthService, appMetrics *metrics.Metrics) {
	log.Printf("Starting both gRPC server on port %d and HTTP server on port %d", cfg.Server.GRPCPort, cfg.Server.HTTPPort)

	// Start gRPC server in goroutine
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
		if err != nil {
			log.Fatalf("Failed to listen on gRPC port: %v", err)
		}

		s := grpcServer.CreateServer()
		log.Printf("gRPC server listening on port %d", cfg.Server.GRPCPort)

		if err := s.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// Start HTTP server in main goroutine
	router := createHTTPRouter(cfg, cfg.Server.GRPCPort, healthService, appMetrics)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler: router,
	}

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down servers...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("HTTP server listening on port %d", cfg.Server.HTTPPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func createHTTPRouter(cfg *config.Config, grpcPort int, healthService *health.HealthService, appMetrics *metrics.Metrics) *gin.Engine {
	// Use the shared metrics instance
	metricsMiddleware := middleware.NewMetricsMiddleware(appMetrics)

	router := gin.Default()

	// Add metrics middleware
	router.Use(metricsMiddleware.HTTPMetrics())
	router.Use(metricsMiddleware.ErrorMetrics())

	// Health check endpoints
	router.GET("/health", func(c *gin.Context) {
		health := healthService.GetCachedHealth()
		statusCode := 200
		if health.Status == "unhealthy" {
			statusCode = 503
		} else if health.Status == "degraded" {
			statusCode = 200 // Still return 200 for degraded but log the issue
		}
		c.JSON(statusCode, health)
	})

	router.GET("/health/detailed", func(c *gin.Context) {
		health := healthService.CheckAll(c.Request.Context())
		statusCode := 200
		if health.Status == "unhealthy" {
			statusCode = 503
		} else if health.Status == "degraded" {
			statusCode = 200
		}
		c.JSON(statusCode, health)
	})

	// Readiness probe (for Kubernetes)
	router.GET("/ready", func(c *gin.Context) {
		health := healthService.GetCachedHealth()
		if health.Status == "unhealthy" {
			c.JSON(503, gin.H{"status": "not ready", "message": "service dependencies are unhealthy"})
			return
		}
		c.JSON(200, gin.H{"status": "ready"})
	})

	// Liveness probe (for Kubernetes)
	router.GET("/live", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "alive",
			"timestamp": time.Now().UTC(),
			"service":   cfg.Service.Name,
			"version":   cfg.Service.Version,
		})
	})

	// Metrics endpoint for Prometheus
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API routes that proxy to gRPC
	api := router.Group("/api/v1")
	{
		// Authentication endpoints
		api.POST("/auth/login", loginHandler(grpcPort))
		api.POST("/auth/logout", logoutHandler(grpcPort))
		api.POST("/auth/register", registerHandler(grpcPort))
		api.POST("/auth/reset-password", resetPasswordHandler(grpcPort))

		// User management endpoints
		api.POST("/users", createUserHandler(grpcPort))
		api.GET("/users/:id", getUserHandler(grpcPort))
		api.PUT("/users/:id", updateUserHandler(grpcPort))
		api.DELETE("/users/:id", deleteUserHandler(grpcPort))
		api.GET("/users", listUsersHandler(grpcPort))

		// Token endpoints
		api.POST("/tokens/introspect", introspectTokenHandler(grpcPort))
		api.POST("/tokens/refresh", refreshTokenHandler(grpcPort))
		api.POST("/tokens/verify", verifyTokenHandler(grpcPort))
	}

	return router
}

// gRPC client helper
func createGRPCClient(grpcPort int) (keycloakv1.KeycloakServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.Dial(
		fmt.Sprintf("localhost:%d", grpcPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, err
	}

	client := keycloakv1.NewKeycloakServiceClient(conn)
	return client, conn, nil
}

// HTTP handlers that proxy to gRPC
func createUserHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.CreateUserRequest
		if bindErr := c.ShouldBindJSON(&req); bindErr != nil {
			c.JSON(400, gin.H{"error": bindErr.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		resp, err := client.CreateUser(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(201, resp)
	}
}

func getUserHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")
		userID := c.Param("id")

		// Validate required parameters
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		req := &keycloakv1.GetUserRequest{
			RealmName:    realmName,
			ClientId:     clientID,
			ClientSecret: clientSecret,
			UserId:       userID,
		}

		resp, err := client.GetUser(c.Request.Context(), req)
		if err != nil {
			c.JSON(404, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func updateUserHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")
		userID := c.Param("id")

		// Validate required parameters
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.UpdateUserRequest
		if bindErr := c.ShouldBindJSON(&req); bindErr != nil {
			c.JSON(400, gin.H{"error": bindErr.Error()})
			return
		}

		// Set realm, client, and user parameters
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret
		req.UserId = userID

		resp, err := client.UpdateUser(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func deleteUserHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")
		userID := c.Param("id")

		// Validate required parameters
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		req := &keycloakv1.DeleteUserRequest{
			RealmName:    realmName,
			ClientId:     clientID,
			ClientSecret: clientSecret,
			UserId:       userID,
		}

		_, err = client.DeleteUser(c.Request.Context(), req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(204, nil)
	}
}

func listUsersHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		// Parse query parameters
		search := c.Query("search")
		email := c.Query("email")
		username := c.Query("username")

		req := &keycloakv1.ListUsersRequest{
			RealmName:    realmName,
			ClientId:     clientID,
			ClientSecret: clientSecret,
			Page:         1,
			PageSize:     10,
			Search:       search,
			Email:        email,
			Username:     username,
		}

		resp, err := client.ListUsers(c.Request.Context(), req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func introspectTokenHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.IntrospectTokenRequest
		if bindErr := c.ShouldBindJSON(&req); bindErr != nil {
			c.JSON(400, gin.H{"error": bindErr.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		resp, err := client.IntrospectToken(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func refreshTokenHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.RefreshTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret
		req.GrantType = "refresh_token"

		resp, err := client.RefreshToken(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func loginHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		resp, err := client.Login(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func logoutHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.LogoutRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		_, err = client.Logout(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "Successfully logged out"})
	}
}

func registerHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		resp, err := client.Register(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, resp)
	}
}

func resetPasswordHandler(grpcPort int) gin.HandlerFunc {
	return func(c *gin.Context) {
		client, conn, err := createGRPCClient(grpcPort)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to connect to gRPC server"})
			return
		}
		defer conn.Close()

		// Extract realm and client parameters from headers
		realmName := c.GetHeader("X-Realm-Name")
		clientID := c.GetHeader("X-Client-Id")
		clientSecret := c.GetHeader("X-Client-Secret")

		// Validate required headers
		if realmName == "" || clientID == "" || clientSecret == "" {
			c.JSON(400, gin.H{"error": "X-Realm-Name, X-Client-Id, and X-Client-Secret headers are required"})
			return
		}

		var req keycloakv1.ResetPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Set realm and client parameters from headers
		req.RealmName = realmName
		req.ClientId = clientID
		req.ClientSecret = clientSecret

		_, err = client.ResetPassword(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "Password reset email sent successfully"})
	}
}

func printUsage() {
	fmt.Println("Usage: ./auth-service [grpc|http|all]")
	fmt.Println("  grpc - Start only gRPC server")
	fmt.Println("  http - Start only HTTP server")
	fmt.Println("  all  - Start both servers (default)")
}
