package storage

//go:generate mockgen -destination mock/mock_repos.go -package mockstorage github.com/kvsuharev/passwordkeeper/internal/server/storage UserRepository,TokenRepository,SecretRepository

import (
	"context"

	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// UserRepository defines persistence operations for user accounts.
type UserRepository interface {
	// Create inserts a new user. Returns errs.ErrAlreadyExists if the login is taken.
	Create(ctx context.Context, user *model.User) error
	// GetByLogin returns the user with the given login, or errs.ErrNotFound.
	GetByLogin(ctx context.Context, login string) (*model.User, error)
	// GetByID returns the user with the given UUID, or errs.ErrNotFound.
	GetByID(ctx context.Context, id string) (*model.User, error)
}

// TokenRepository defines persistence operations for refresh tokens.
type TokenRepository interface {
	// Create stores a new refresh token record.
	Create(ctx context.Context, token *model.RefreshToken) error
	// GetByHash returns the refresh token record for the given SHA-256 hash, or errs.ErrNotFound.
	GetByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	// Delete removes the refresh token with the given hash.
	Delete(ctx context.Context, hash string) error
}
