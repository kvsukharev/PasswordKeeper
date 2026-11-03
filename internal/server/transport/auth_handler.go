package transport

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/server/service"
)

// AuthHandler implements pb.AuthServiceServer.
type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	svc service.AuthService
}

// NewAuthHandler creates an AuthHandler wired to the given AuthService.
func NewAuthHandler(svc service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// Register creates a new user account and returns an initial token pair.
func (h *AuthHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.TokenPair, error) {
	if req.GetLogin() == "" || len(req.GetAuthKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "login and auth_key are required")
	}

	pair, err := h.svc.Register(ctx, req.GetLogin(), req.GetAuthKey())
	if err != nil {
		return nil, mapError(err)
	}

	return &pb.TokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    timestamppb.New(pair.ExpiresAt),
	}, nil
}

// Login authenticates a user and returns a token pair.
func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.TokenPair, error) {
	if req.GetLogin() == "" || len(req.GetAuthKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "login and auth_key are required")
	}

	pair, err := h.svc.Login(ctx, req.GetLogin(), req.GetAuthKey())
	if err != nil {
		return nil, mapError(err)
	}

	return &pb.TokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    timestamppb.New(pair.ExpiresAt),
	}, nil
}

// Refresh exchanges a valid refresh token for a new token pair.
func (h *AuthHandler) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.TokenPair, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	pair, err := h.svc.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, mapError(err)
	}

	return &pb.TokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    timestamppb.New(pair.ExpiresAt),
	}, nil
}

// Logout invalidates the given refresh token.
func (h *AuthHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*emptypb.Empty, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	if err := h.svc.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, mapError(err)
	}

	return &emptypb.Empty{}, nil
}
