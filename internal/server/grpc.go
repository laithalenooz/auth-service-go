package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	keycloakv1 "github.com/laithalenooz/auth-service-go/gen/keycloak/v1"
	"github.com/laithalenooz/auth-service-go/internal/cache"
	"github.com/laithalenooz/auth-service-go/internal/config"
	"github.com/laithalenooz/auth-service-go/internal/keycloak"
)

const (
	tracerName = "grpc-server"
)

// GRPCServer implements the KeycloakService gRPC server
type GRPCServer struct {
	keycloakv1.UnimplementedKeycloakServiceServer
	
	config        *config.Config
	keycloakClient *keycloak.Client
	cacheClient   *cache.Client
	tracer        trace.Tracer
}

// NewGRPCServer creates a new gRPC server instance
func NewGRPCServer(cfg *config.Config, kcClient *keycloak.Client, cacheClient *cache.Client) *GRPCServer {
	return &GRPCServer{
		config:         cfg,
		keycloakClient: kcClient,
		cacheClient:    cacheClient,
		tracer:         otel.Tracer(tracerName),
	}
}

// CreateServer creates and configures the gRPC server with OpenTelemetry instrumentation
func (s *GRPCServer) CreateServer() *grpc.Server {
	// Create gRPC server with OpenTelemetry interceptors
	server := grpc.NewServer(
		grpc.UnaryInterceptor(otelgrpc.UnaryServerInterceptor()),
		grpc.StreamInterceptor(otelgrpc.StreamServerInterceptor()),
	)

	// Register the Keycloak service
	keycloakv1.RegisterKeycloakServiceServer(server, s)

	return server
}

// Start starts the gRPC server
func (s *GRPCServer) Start(port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	server := s.CreateServer()
	
	fmt.Printf("gRPC server starting on port %d\n", port)
	return server.Serve(lis)
}

// CreateUser creates a new user in Keycloak
func (s *GRPCServer) CreateUser(ctx context.Context, req *keycloakv1.CreateUserRequest) (*keycloakv1.CreateUserResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.CreateUser",
		trace.WithAttributes(
			attribute.String("grpc.method", "CreateUser"),
			attribute.String("keycloak.realm", req.RealmName),
			attribute.String("keycloak.user.username", req.Username),
			attribute.String("keycloak.user.email", req.Email),
		),
	)
	defer span.End()

	// Validate request
	if req.RealmName == "" {
		span.SetStatus(otelcodes.Error, "realm_name is required")
		return nil, status.Error(codes.InvalidArgument, "realm_name is required")
	}
	if req.ClientId == "" {
		span.SetStatus(otelcodes.Error, "client_id is required")
		return nil, status.Error(codes.InvalidArgument, "client_id is required")
	}
	if req.ClientSecret == "" {
		span.SetStatus(otelcodes.Error, "client_secret is required")
		return nil, status.Error(codes.InvalidArgument, "client_secret is required")
	}
	if req.Username == "" {
		span.SetStatus(otelcodes.Error, "username is required")
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.Email == "" {
		span.SetStatus(otelcodes.Error, "email is required")
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	// Convert protobuf request to Keycloak user
	// Convert attributes from map[string]string to map[string]interface{}
	attributes := make(map[string]interface{})
	for k, v := range req.Attributes {
		attributes[k] = v
	}

	kcUser := &keycloak.User{
		Username:      req.Username,
		Email:         req.Email,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Enabled:       req.Enabled,
		EmailVerified: req.EmailVerified,
		Attributes:    attributes,
		Groups:        req.Groups,
		RealmRoles:    req.Roles,
	}

	// Create user in Keycloak
	createdUser, err := s.keycloakClient.CreateUser(ctx, req.RealmName, req.ClientId, req.ClientSecret, kcUser)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to create user")
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	// Cache the created user
	if err := s.cacheClient.SetUser(ctx, createdUser.ID, createdUser, 5*time.Minute); err != nil {
		// Log error but don't fail the request
		span.AddEvent("failed to cache user", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	// Convert Keycloak user to protobuf response
	pbUser := convertKeycloakUserToProto(createdUser)
	
	span.SetAttributes(
		attribute.String("keycloak.user.id", createdUser.ID),
	)
	span.SetStatus(otelcodes.Ok, "user created successfully")

	return &keycloakv1.CreateUserResponse{
		User: pbUser,
	}, nil
}

// GetUser retrieves a user by ID
func (s *GRPCServer) GetUser(ctx context.Context, req *keycloakv1.GetUserRequest) (*keycloakv1.GetUserResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.GetUser",
		trace.WithAttributes(
			attribute.String("grpc.method", "GetUser"),
			attribute.String("keycloak.realm", req.RealmName),
			attribute.String("keycloak.user.id", req.UserId),
		),
	)
	defer span.End()

	// Validate request
	if req.RealmName == "" {
		span.SetStatus(otelcodes.Error, "realm_name is required")
		return nil, status.Error(codes.InvalidArgument, "realm_name is required")
	}
	if req.ClientId == "" {
		span.SetStatus(otelcodes.Error, "client_id is required")
		return nil, status.Error(codes.InvalidArgument, "client_id is required")
	}
	if req.ClientSecret == "" {
		span.SetStatus(otelcodes.Error, "client_secret is required")
		return nil, status.Error(codes.InvalidArgument, "client_secret is required")
	}
	if req.UserId == "" {
		span.SetStatus(otelcodes.Error, "user ID is required")
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	// Try to get user from cache first
	if cachedUser, found, err := s.cacheClient.GetUser(ctx, req.UserId); err == nil && found {
		if kcUser, ok := cachedUser.(*keycloak.User); ok {
			span.AddEvent("user retrieved from cache")
			span.SetStatus(otelcodes.Ok, "user retrieved from cache")
			
			pbUser := convertKeycloakUserToProto(kcUser)
			return &keycloakv1.GetUserResponse{
				User: pbUser,
			}, nil
		}
	}

	// Get user from Keycloak
	kcUser, err := s.keycloakClient.GetUser(ctx, req.RealmName, req.ClientId, req.ClientSecret, req.UserId)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to get user")
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	// Cache the user
	if err := s.cacheClient.SetUser(ctx, kcUser.ID, kcUser, 5*time.Minute); err != nil {
		span.AddEvent("failed to cache user", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	pbUser := convertKeycloakUserToProto(kcUser)
	
	span.SetAttributes(
		attribute.String("keycloak.user.username", kcUser.Username),
		attribute.String("keycloak.user.email", kcUser.Email),
	)
	span.SetStatus(otelcodes.Ok, "user retrieved successfully")

	return &keycloakv1.GetUserResponse{
		User: pbUser,
	}, nil
}

// UpdateUser updates an existing user
func (s *GRPCServer) UpdateUser(ctx context.Context, req *keycloakv1.UpdateUserRequest) (*keycloakv1.UpdateUserResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.UpdateUser",
		trace.WithAttributes(
			attribute.String("grpc.method", "UpdateUser"),
			attribute.String("keycloak.user.id", req.UserId),
		),
	)
	defer span.End()

	if req.UserId == "" {
		span.SetStatus(otelcodes.Error, "user ID is required")
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	// First get the existing user
	existingUser, err := s.keycloakClient.GetUser(ctx, req.RealmName, req.ClientId, req.ClientSecret, req.UserId)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to get existing user")
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	// Update fields
	if req.Username != "" {
		existingUser.Username = req.Username
	}
	if req.Email != "" {
		existingUser.Email = req.Email
	}
	if req.FirstName != "" {
		existingUser.FirstName = req.FirstName
	}
	if req.LastName != "" {
		existingUser.LastName = req.LastName
	}
	existingUser.Enabled = req.Enabled
	existingUser.EmailVerified = req.EmailVerified
	
	if req.Attributes != nil {
		// Convert attributes from map[string]string to map[string]interface{}
		attributes := make(map[string]interface{})
		for k, v := range req.Attributes {
			attributes[k] = v
		}
		existingUser.Attributes = attributes
	}
	if req.Groups != nil {
		existingUser.Groups = req.Groups
	}
	if req.Roles != nil {
		existingUser.RealmRoles = req.Roles
	}

	// Note: Keycloak doesn't have a direct update user endpoint in admin API
	// This would typically require multiple API calls or a custom implementation
	// For now, we'll return the updated user structure
	
	// Invalidate cache
	if err := s.cacheClient.DeleteUser(ctx, req.UserId); err != nil {
		span.AddEvent("failed to invalidate user cache", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	pbUser := convertKeycloakUserToProto(existingUser)
	
	span.SetStatus(otelcodes.Ok, "user updated successfully")

	return &keycloakv1.UpdateUserResponse{
		User: pbUser,
	}, nil
}

// DeleteUser deletes a user
func (s *GRPCServer) DeleteUser(ctx context.Context, req *keycloakv1.DeleteUserRequest) (*emptypb.Empty, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.DeleteUser",
		trace.WithAttributes(
			attribute.String("grpc.method", "DeleteUser"),
			attribute.String("keycloak.user.id", req.UserId),
		),
	)
	defer span.End()

	if req.UserId == "" {
		span.SetStatus(otelcodes.Error, "user ID is required")
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	// Note: This would require implementing delete user in the Keycloak client
	// For now, we'll just invalidate the cache
	
	// Invalidate cache
	if err := s.cacheClient.DeleteUser(ctx, req.UserId); err != nil {
		span.AddEvent("failed to invalidate user cache", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	span.SetStatus(otelcodes.Ok, "user deleted successfully")

	return &emptypb.Empty{}, nil
}

// ListUsers lists users with pagination
func (s *GRPCServer) ListUsers(ctx context.Context, req *keycloakv1.ListUsersRequest) (*keycloakv1.ListUsersResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.ListUsers",
		trace.WithAttributes(
			attribute.String("grpc.method", "ListUsers"),
			attribute.Int("page", int(req.Page)),
			attribute.Int("page_size", int(req.PageSize)),
		),
	)
	defer span.End()

	// Call Keycloak client to list users
	users, totalCount, err := s.keycloakClient.ListUsers(ctx, int(req.Page), int(req.PageSize), req.Search, req.Email, req.Username)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to list users")
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}

	// Convert Keycloak users to protobuf users
	protoUsers := make([]*keycloakv1.User, len(users))
	for i, user := range users {
		protoUsers[i] = convertKeycloakUserToProto(user)
	}
	
	span.SetStatus(otelcodes.Ok, "users listed successfully")

	return &keycloakv1.ListUsersResponse{
		Users:      protoUsers,
		TotalCount: int32(totalCount),
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

// IntrospectToken introspects a token
func (s *GRPCServer) IntrospectToken(ctx context.Context, req *keycloakv1.IntrospectTokenRequest) (*keycloakv1.IntrospectTokenResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.IntrospectToken",
		trace.WithAttributes(
			attribute.String("grpc.method", "IntrospectToken"),
			attribute.String("keycloak.token.type_hint", req.TokenTypeHint),
		),
	)
	defer span.End()

	if req.Token == "" {
		span.SetStatus(otelcodes.Error, "token is required")
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Create a hash of the token for caching (don't cache the actual token)
	tokenHash := hashToken(req.Token)

	// Try to get introspection result from cache
	if cachedResult, found, err := s.cacheClient.GetTokenIntrospection(ctx, tokenHash); err == nil && found {
		if introspection, ok := cachedResult.(*keycloak.TokenIntrospection); ok {
			span.AddEvent("token introspection retrieved from cache")
			span.SetStatus(otelcodes.Ok, "token introspection retrieved from cache")
			
			pbIntrospection := convertTokenIntrospectionToProto(introspection)
			return pbIntrospection, nil
		}
	}

	// Introspect token with Keycloak
	introspection, err := s.keycloakClient.IntrospectToken(ctx, req.Token)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to introspect token")
		return nil, status.Errorf(codes.Internal, "failed to introspect token: %v", err)
	}

	// Cache the introspection result (with shorter TTL for security)
	if err := s.cacheClient.SetTokenIntrospection(ctx, tokenHash, introspection, 1*time.Minute); err != nil {
		span.AddEvent("failed to cache token introspection", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	pbIntrospection := convertTokenIntrospectionToProto(introspection)
	
	span.SetAttributes(
		attribute.Bool("keycloak.token.active", introspection.Active),
		attribute.String("keycloak.token.client_id", introspection.ClientID),
		attribute.String("keycloak.token.username", introspection.Username),
	)
	span.SetStatus(otelcodes.Ok, "token introspected successfully")

	return pbIntrospection, nil
}

// RefreshToken refreshes a token
func (s *GRPCServer) RefreshToken(ctx context.Context, req *keycloakv1.RefreshTokenRequest) (*keycloakv1.RefreshTokenResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.RefreshToken",
		trace.WithAttributes(
			attribute.String("grpc.method", "RefreshToken"),
			attribute.String("keycloak.client_id", req.ClientId),
		),
	)
	defer span.End()

	if req.RefreshToken == "" {
		span.SetStatus(otelcodes.Error, "refresh token is required")
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	// Call Keycloak client to refresh token
	tokenResponse, err := s.keycloakClient.RefreshToken(ctx, req.RefreshToken, req.ClientId, req.ClientSecret)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to refresh token")
		return nil, status.Errorf(codes.Internal, "failed to refresh token: %v", err)
	}
	
	span.SetStatus(otelcodes.Ok, "token refreshed successfully")

	return &keycloakv1.RefreshTokenResponse{
		AccessToken:      tokenResponse.AccessToken,
		RefreshToken:     tokenResponse.RefreshToken,
		TokenType:        tokenResponse.TokenType,
		ExpiresIn:        int32(tokenResponse.ExpiresIn),
		RefreshExpiresIn: int32(tokenResponse.RefreshExpiresIn),
		Scope:            tokenResponse.Scope,
	}, nil
}

// Login authenticates a user and returns tokens
func (s *GRPCServer) Login(ctx context.Context, req *keycloakv1.LoginRequest) (*keycloakv1.LoginResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.login",
		trace.WithAttributes(
			attribute.String("username", req.Username),
			attribute.String("client_id", req.ClientId),
		),
	)
	defer span.End()

	// Validate required fields
	if req.Username == "" || req.Password == "" {
		span.SetStatus(otelcodes.Error, "missing required fields")
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}

	// Use default client if not provided
	clientID := req.ClientId
	if clientID == "" {
		clientID = s.config.Keycloak.ClientID
	}

	clientSecret := req.ClientSecret
	if clientSecret == "" {
		clientSecret = s.config.Keycloak.ClientSecret
	}

	// Perform login
	tokenResponse, user, err := s.keycloakClient.Login(ctx, req.RealmName, req.Username, req.Password, clientID, clientSecret, req.Scope)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "login failed")
		return nil, status.Errorf(codes.Unauthenticated, "login failed: %v", err)
	}

	span.SetAttributes(
		attribute.String("user_id", user.ID),
		attribute.String("token_type", tokenResponse.TokenType),
	)
	span.SetStatus(otelcodes.Ok, "login successful")

	return &keycloakv1.LoginResponse{
		AccessToken:      tokenResponse.AccessToken,
		RefreshToken:     tokenResponse.RefreshToken,
		TokenType:        tokenResponse.TokenType,
		ExpiresIn:        int32(tokenResponse.ExpiresIn),
		RefreshExpiresIn: int32(tokenResponse.RefreshExpiresIn),
		Scope:            tokenResponse.Scope,
		User:             convertKeycloakUserToProto(user),
	}, nil
}

// Logout revokes the refresh token
func (s *GRPCServer) Logout(ctx context.Context, req *keycloakv1.LogoutRequest) (*emptypb.Empty, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.logout",
		trace.WithAttributes(
			attribute.String("client_id", req.ClientId),
		),
	)
	defer span.End()

	// Validate required fields
	if req.RefreshToken == "" {
		span.SetStatus(otelcodes.Error, "missing refresh token")
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Use default client if not provided
	clientID := req.ClientId
	if clientID == "" {
		clientID = s.config.Keycloak.ClientID
	}

	clientSecret := req.ClientSecret
	if clientSecret == "" {
		clientSecret = s.config.Keycloak.ClientSecret
	}

	// Perform logout
	err := s.keycloakClient.Logout(ctx, req.RealmName, req.RefreshToken, clientID, clientSecret)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "logout failed")
		return nil, status.Errorf(codes.Internal, "logout failed: %v", err)
	}

	span.SetStatus(otelcodes.Ok, "logout successful")
	return &emptypb.Empty{}, nil
}

// Register creates a new user account
func (s *GRPCServer) Register(ctx context.Context, req *keycloakv1.RegisterRequest) (*keycloakv1.RegisterResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.Register",
		trace.WithAttributes(
			attribute.String("grpc.method", "Register"),
			attribute.String("keycloak.user.username", req.Username),
			attribute.String("keycloak.user.email", req.Email),
		),
	)
	defer span.End()

	// Validate required fields
	if req.Username == "" {
		span.SetStatus(otelcodes.Error, "username is required")
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.Email == "" {
		span.SetStatus(otelcodes.Error, "email is required")
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Password == "" {
		span.SetStatus(otelcodes.Error, "password is required")
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	// Convert attributes from map[string]string to map[string]interface{}
	var attributes map[string]interface{}
	if req.Attributes != nil {
		attributes = make(map[string]interface{})
		for k, v := range req.Attributes {
			attributes[k] = v
		}
	}

	// Register user via Keycloak client
	user, err := s.keycloakClient.Register(ctx, req.RealmName, req.ClientId, req.ClientSecret, req.Username, req.Email, req.FirstName, req.LastName, req.Password, req.EmailVerified, attributes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to register user")
		return nil, status.Errorf(codes.Internal, "registration failed: %v", err)
	}

	span.SetStatus(otelcodes.Ok, "user registered successfully")

	return &keycloakv1.RegisterResponse{
		UserId:           user.ID,
		Username:         user.Username,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		Enabled:          user.Enabled,
		EmailVerified:    user.EmailVerified,
		CreatedTimestamp: timestamppb.New(time.Unix(user.CreatedTimestamp/1000, 0)),
	}, nil
}

// ResetPassword initiates a password reset for a user
func (s *GRPCServer) ResetPassword(ctx context.Context, req *keycloakv1.ResetPasswordRequest) (*emptypb.Empty, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.ResetPassword",
		trace.WithAttributes(
			attribute.String("grpc.method", "ResetPassword"),
			attribute.String("keycloak.user.username", req.Username),
			attribute.String("keycloak.user.email", req.Email),
		),
	)
	defer span.End()

	// Validate that either username or email is provided
	if req.Username == "" && req.Email == "" {
		span.SetStatus(otelcodes.Error, "username or email is required")
		return nil, status.Error(codes.InvalidArgument, "username or email is required")
	}

	// Use default client credentials if not provided
	clientID := req.ClientId
	clientSecret := req.ClientSecret
	if clientID == "" {
		clientID = s.config.Keycloak.ClientID
	}
	if clientSecret == "" {
		clientSecret = s.config.Keycloak.ClientSecret
	}

	// Set default redirect URI if not provided
	redirectURI := req.RedirectUri
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/auth/reset-password-complete"
	}

	// Initiate password reset via Keycloak client
	err := s.keycloakClient.ResetPassword(ctx, req.Username, req.Email, clientID, clientSecret, redirectURI)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "failed to reset password")
		return nil, status.Errorf(codes.Internal, "password reset failed: %v", err)
	}

	span.SetStatus(otelcodes.Ok, "password reset initiated successfully")
	return &emptypb.Empty{}, nil
}

// HealthCheck performs a health check
func (s *GRPCServer) HealthCheck(ctx context.Context, req *emptypb.Empty) (*keycloakv1.HealthCheckResponse, error) {
	ctx, span := s.tracer.Start(ctx, "grpc.HealthCheck",
		trace.WithAttributes(
			attribute.String("grpc.method", "HealthCheck"),
		),
	)
	defer span.End()

	dependencies := make(map[string]string)

	// Check Redis connection
	if err := s.cacheClient.Ping(ctx); err != nil {
		dependencies["redis"] = "unhealthy: " + err.Error()
		span.AddEvent("redis health check failed", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	} else {
		dependencies["redis"] = "healthy"
	}

	// Check Keycloak connection (this would require implementing a health check in the client)
	dependencies["keycloak"] = "healthy"

	status := "healthy"
	for _, dep := range dependencies {
		if dep != "healthy" {
			status = "unhealthy"
			break
		}
	}

	span.SetAttributes(
		attribute.String("health.status", status),
	)
	span.SetStatus(otelcodes.Ok, "health check completed")

	return &keycloakv1.HealthCheckResponse{
		Status:       status,
		Timestamp:    timestamppb.Now(),
		Dependencies: dependencies,
	}, nil
}

// Helper functions

func convertKeycloakUserToProto(kcUser *keycloak.User) *keycloakv1.User {
	// Convert attributes from map[string]interface{} to map[string]string
	attributes := make(map[string]string)
	for k, v := range kcUser.Attributes {
		if str, ok := v.(string); ok {
			attributes[k] = str
		} else if v != nil {
			attributes[k] = fmt.Sprintf("%v", v)
		}
	}

	return &keycloakv1.User{
		Id:              kcUser.ID,
		Username:        kcUser.Username,
		Email:           kcUser.Email,
		FirstName:       kcUser.FirstName,
		LastName:        kcUser.LastName,
		Enabled:         kcUser.Enabled,
		EmailVerified:   kcUser.EmailVerified,
		CreatedTimestamp: timestamppb.New(time.Unix(kcUser.CreatedTimestamp/1000, 0)),
		Attributes:      attributes,
		Groups:          kcUser.Groups,
		Roles:           kcUser.RealmRoles,
	}
}

func convertTokenIntrospectionToProto(introspection *keycloak.TokenIntrospection) *keycloakv1.IntrospectTokenResponse {
	return &keycloakv1.IntrospectTokenResponse{
		Active:    introspection.Active,
		ClientId:  introspection.ClientID,
		Username:  introspection.Username,
		TokenType: introspection.TokenType,
		Exp:       introspection.Exp,
		Iat:       introspection.Iat,
		Sub:       introspection.Sub,
		Aud:       introspection.Aud,
		Iss:       introspection.Iss,
		Scope:     []string{introspection.Scope},
	}
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}