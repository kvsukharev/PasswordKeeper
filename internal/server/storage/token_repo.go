package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// tokenRepo is the PostgreSQL implementation of TokenRepository.
type tokenRepo struct {
	db *pgxpool.Pool
}

// NewTokenRepo creates a TokenRepository backed by the given pool.
func NewTokenRepo(db *pgxpool.Pool) TokenRepository {
	return &tokenRepo{db: db}
}

// Create inserts a new refresh token record.
func (r *tokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (token_hash, user_id, expires_at)
		VALUES ($1, $2, $3)`

	_, err := r.db.Exec(ctx, q, token.TokenHash, token.UserID, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

// GetByHash fetches the refresh token for the given SHA-256 hex hash.
// Returns errs.ErrNotFound if no matching record exists.
func (r *tokenRepo) GetByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	const q = `
		SELECT token_hash, user_id, expires_at
		FROM refresh_tokens WHERE token_hash = $1`

	rt := &model.RefreshToken{}
	err := r.db.QueryRow(ctx, q, hash).Scan(&rt.TokenHash, &rt.UserID, &rt.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return rt, nil
}

// Delete removes the refresh token with the given hash.
func (r *tokenRepo) Delete(ctx context.Context, hash string) error {
	const q = `DELETE FROM refresh_tokens WHERE token_hash = $1`

	_, err := r.db.Exec(ctx, q, hash)
	if err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}
	return nil
}
