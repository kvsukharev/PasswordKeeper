package service

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
	"github.com/kvsuharev/passwordkeeper/internal/server/storage"
)

// authService implements AuthService.
type authService struct {
	users    storage.UserRepository
	tokens   storage.TokenRepository
	tokenMgr *auth.Manager
}

// NewAuthService creates an AuthService wired to the given repositories and
// token manager.
func NewAuthService(
	users storage.UserRepository,
	tokens storage.TokenRepository,
	tokenMgr *auth.Manager,
) AuthService {
	return &authService{
		users:    users,
		tokens:   tokens,
		tokenMgr: tokenMgr,
	}
}

// Register creates a new user and issues an initial token pair.
func (s *authService) Register(ctx context.Context, login string, authKey []byte) (*model.TokenPair, error) {
	if err := validateLogin(login); err != nil {
		return nil, fmt.Errorf("%w: %s", errs.ErrInvalidArgument, err)
	}

	hash, err := auth.HashAuthKey(authKey)
	if err != nil {
		return nil, fmt.Errorf("hash auth key: %w", err)
	}

	user := &model.User{
		ID:           uuid.New().String(),
		Login:        login,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, errs.ErrAlreadyExists) {
			return nil, errs.ErrAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return s.issueTokenPair(ctx, user.ID)
}

// Login authenticates a user by login and auth_key, issuing a fresh token pair.
func (s *authService) Login(ctx context.Context, login string, authKey []byte) (*model.TokenPair, error) {
	user, err := s.users.GetByLogin(ctx, login)
	if err != nil {
		// Do not reveal whether the login exists.
		return nil, errs.ErrUnauthenticated
	}

	ok, err := auth.VerifyAuthKey(authKey, user.PasswordHash)
	if err != nil || !ok {
		return nil, errs.ErrUnauthenticated
	}

	return s.issueTokenPair(ctx, user.ID)
}

// Refresh rotates the refresh token and returns a new token pair.
func (s *authService) Refresh(ctx context.Context, rawToken string) (*model.TokenPair, error) {
	hash, err := auth.HashRefreshToken(rawToken)
	if err != nil {
		return nil, errs.ErrUnauthenticated
	}

	rt, err := s.tokens.GetByHash(ctx, hash)
	if err != nil {
		return nil, errs.ErrUnauthenticated
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.tokens.Delete(ctx, hash)
		return nil, errs.ErrUnauthenticated
	}

	// Rotate: delete old token before issuing new one.
	if err := s.tokens.Delete(ctx, hash); err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	return s.issueTokenPair(ctx, rt.UserID)
}

// Logout invalidates the given refresh token. Errors are ignored silently to
// avoid leaking token existence information.
func (s *authService) Logout(ctx context.Context, rawToken string) error {
	hash, err := auth.HashRefreshToken(rawToken)
	if err != nil {
		return nil
	}
	_ = s.tokens.Delete(ctx, hash)
	return nil
}

// issueTokenPair generates a new access+refresh token pair for the given user.
func (s *authService) issueTokenPair(ctx context.Context, userID string) (*model.TokenPair, error) {
	accessToken, expiresAt, err := s.tokenMgr.GenerateAccessToken(userID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	rawRefresh, hashRefresh, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	rt := &model.RefreshToken{
		TokenHash: hashRefresh,
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.tokenMgr.RefreshTTL()).UTC(),
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresAt:    expiresAt,
	}, nil
}

// validateLogin checks that a login meets length requirements (3–64 characters).
func validateLogin(login string) error {
	n := utf8.RuneCountInString(login)
	if n < 3 || n > 64 {
		return fmt.Errorf("login must be 3–64 characters, got %d", n)
	}
	return nil
}
