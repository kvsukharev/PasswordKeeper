package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
	"github.com/kvsuharev/passwordkeeper/internal/server/service"
	mockstorage "github.com/kvsuharev/passwordkeeper/internal/server/storage/mock"
)

func newTokenMgr() *auth.Manager {
	return auth.NewManager("test-jwt-secret-long-enough-here", 15*time.Minute, 30*24*time.Hour)
}

func newAuthSvc(ctrl *gomock.Controller) (service.AuthService, *mockstorage.MockUserRepository, *mockstorage.MockTokenRepository) {
	users := mockstorage.NewMockUserRepository(ctrl)
	tokens := mockstorage.NewMockTokenRepository(ctrl)
	svc := service.NewAuthService(users, tokens, newTokenMgr())
	return svc, users, tokens
}

func TestRegister(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, tokens := newAuthSvc(ctrl)

		users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		pair, err := svc.Register(context.Background(), "alice", []byte("auth-key"))
		require.NoError(t, err)
		assert.NotEmpty(t, pair.AccessToken)
		assert.NotEmpty(t, pair.RefreshToken)
	})

	t.Run("repo error returns wrapped error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, _ := newAuthSvc(ctrl)

		users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(assert.AnError)

		_, err := svc.Register(context.Background(), "alice", []byte("auth-key"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create user")
	})

	t.Run("duplicate login returns ErrAlreadyExists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, _ := newAuthSvc(ctrl)

		users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errs.ErrAlreadyExists)

		_, err := svc.Register(context.Background(), "alice", []byte("auth-key"))
		require.ErrorIs(t, err, errs.ErrAlreadyExists)
	})

	t.Run("short login returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, _ := newAuthSvc(ctrl)

		_, err := svc.Register(context.Background(), "ab", []byte("auth-key"))
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})

	t.Run("long login returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, _ := newAuthSvc(ctrl)

		_, err := svc.Register(context.Background(), string(make([]byte, 65)), []byte("auth-key"))
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})
}

func TestLogin(t *testing.T) {
	t.Parallel()

	const rawKey = "auth-key-for-login-test"

	// Prepare a valid hash so we can test login success.
	validHash, err := auth.HashAuthKey([]byte(rawKey))
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, tokens := newAuthSvc(ctrl)

		users.EXPECT().GetByLogin(gomock.Any(), "alice").Return(&model.User{
			ID:           "user-1",
			Login:        "alice",
			PasswordHash: validHash,
		}, nil)
		tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		pair, err := svc.Login(context.Background(), "alice", []byte(rawKey))
		require.NoError(t, err)
		assert.NotEmpty(t, pair.AccessToken)
	})

	t.Run("unknown login returns ErrUnauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, _ := newAuthSvc(ctrl)

		users.EXPECT().GetByLogin(gomock.Any(), "nobody").Return(nil, errs.ErrNotFound)

		_, err := svc.Login(context.Background(), "nobody", []byte("any"))
		require.ErrorIs(t, err, errs.ErrUnauthenticated)
	})

	t.Run("wrong auth_key returns ErrUnauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, _ := newAuthSvc(ctrl)

		users.EXPECT().GetByLogin(gomock.Any(), "alice").Return(&model.User{
			ID:           "user-1",
			Login:        "alice",
			PasswordHash: validHash,
		}, nil)

		_, err := svc.Login(context.Background(), "alice", []byte("wrong-key"))
		require.ErrorIs(t, err, errs.ErrUnauthenticated)
	})
}

func TestRefresh(t *testing.T) {
	t.Parallel()

	t.Run("invalid base64 token returns ErrUnauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, _ := newAuthSvc(ctrl)

		_, err := svc.Refresh(context.Background(), "not-base64!!!")
		require.ErrorIs(t, err, errs.ErrUnauthenticated)
	})

	t.Run("valid token is rotated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, tokens := newAuthSvc(ctrl)

		rawToken, tokenHash, err := auth.GenerateRefreshToken()
		require.NoError(t, err)

		tokens.EXPECT().GetByHash(gomock.Any(), tokenHash).Return(&model.RefreshToken{
			TokenHash: tokenHash,
			UserID:    "user-1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)
		tokens.EXPECT().Delete(gomock.Any(), tokenHash).Return(nil)
		tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		pair, err := svc.Refresh(context.Background(), rawToken)
		require.NoError(t, err)
		assert.NotEmpty(t, pair.AccessToken)
	})

	t.Run("expired token returns ErrUnauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, tokens := newAuthSvc(ctrl)

		rawToken, tokenHash, err := auth.GenerateRefreshToken()
		require.NoError(t, err)

		tokens.EXPECT().GetByHash(gomock.Any(), tokenHash).Return(&model.RefreshToken{
			TokenHash: tokenHash,
			UserID:    "user-1",
			ExpiresAt: time.Now().Add(-time.Hour), // expired
		}, nil)
		tokens.EXPECT().Delete(gomock.Any(), tokenHash).Return(nil)

		_, err = svc.Refresh(context.Background(), rawToken)
		require.ErrorIs(t, err, errs.ErrUnauthenticated)
	})

	t.Run("delete error during rotation returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, tokens := newAuthSvc(ctrl)

		rawToken, tokenHash, err := auth.GenerateRefreshToken()
		require.NoError(t, err)

		tokens.EXPECT().GetByHash(gomock.Any(), tokenHash).Return(&model.RefreshToken{
			TokenHash: tokenHash,
			UserID:    "user-1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)
		tokens.EXPECT().Delete(gomock.Any(), tokenHash).Return(assert.AnError)

		_, err = svc.Refresh(context.Background(), rawToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotate refresh token")
	})

	t.Run("token store error during issue returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, users, tokens := newAuthSvc(ctrl)

		users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		tokens.EXPECT().Create(gomock.Any(), gomock.Any()).Return(assert.AnError)

		_, err := svc.Register(context.Background(), "alice", []byte("auth-key"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "store refresh token")
	})

	t.Run("unknown token returns ErrUnauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, tokens := newAuthSvc(ctrl)

		rawToken, tokenHash, err := auth.GenerateRefreshToken()
		require.NoError(t, err)

		tokens.EXPECT().GetByHash(gomock.Any(), tokenHash).Return(nil, errs.ErrNotFound)

		_, err = svc.Refresh(context.Background(), rawToken)
		require.ErrorIs(t, err, errs.ErrUnauthenticated)
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()

	t.Run("valid token is deleted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, tokens := newAuthSvc(ctrl)

		rawToken, tokenHash, err := auth.GenerateRefreshToken()
		require.NoError(t, err)

		tokens.EXPECT().Delete(gomock.Any(), tokenHash).Return(nil)

		err = svc.Logout(context.Background(), rawToken)
		require.NoError(t, err)
	})

	t.Run("invalid token is silently ignored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, _ := newAuthSvc(ctrl)

		err := svc.Logout(context.Background(), "not-valid-base64!!!")
		require.NoError(t, err)
	})
}
