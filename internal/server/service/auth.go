package service

//go:generate mockgen -destination mock/mock_auth.go -package mockservice github.com/kvsuharev/passwordkeeper/internal/server/service AuthService

import (
	"context"

	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// AuthService defines the business logic for user authentication.
type AuthService interface {
	// Register creates a new user account and returns an initial token pair.
	// Returns errs.ErrAlreadyExists if the login is already taken, or
	// errs.ErrInvalidArgument if the login fails validation.
	Register(ctx context.Context, login string, authKey []byte) (*model.TokenPair, error)

	// Login authenticates a user and returns a token pair.
	// Always returns errs.ErrUnauthenticated on failure to avoid revealing
	// whether the login exists.
	Login(ctx context.Context, login string, authKey []byte) (*model.TokenPair, error)

	// Refresh exchanges a valid refresh token for a new token pair.
	// The old refresh token is invalidated (rotation).
	// Returns errs.ErrUnauthenticated if the token is invalid or expired.
	Refresh(ctx context.Context, refreshToken string) (*model.TokenPair, error)

	// Logout invalidates the given refresh token.
	Logout(ctx context.Context, refreshToken string) error
}
