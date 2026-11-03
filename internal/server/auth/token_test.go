package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
)

func newManager() *auth.Manager {
	return auth.NewManager("test-secret-32-bytes-long-at-min", 15*time.Minute, 30*24*time.Hour)
}

func TestGenerateAndValidateAccessToken(t *testing.T) {
	t.Parallel()

	mgr := newManager()
	userID := "user-uuid-1234"

	token, expiresAt, err := mgr.GenerateAccessToken(userID)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, expiresAt.After(time.Now()))

	t.Run("valid token returns userID", func(t *testing.T) {
		got, err := mgr.ValidateAccessToken(token)
		require.NoError(t, err)
		assert.Equal(t, userID, got)
	})

	t.Run("tampered token is rejected", func(t *testing.T) {
		_, err := mgr.ValidateAccessToken(token + "x")
		require.Error(t, err)
	})

	t.Run("token signed with different secret is rejected", func(t *testing.T) {
		other := auth.NewManager("other-secret-value-here-12345678", 15*time.Minute, 30*24*time.Hour)
		_, err := other.ValidateAccessToken(token)
		require.Error(t, err)
	})
}

func TestRefreshTTL(t *testing.T) {
	t.Parallel()

	ttl := 30 * 24 * time.Hour
	mgr := auth.NewManager("test-secret-32-bytes-long-at-min", 15*time.Minute, ttl)
	assert.Equal(t, ttl, mgr.RefreshTTL())
}

func TestValidateAccessToken_Expired(t *testing.T) {
	t.Parallel()

	mgr := auth.NewManager("test-secret-32-bytes-long-at-min", -time.Minute, 30*24*time.Hour)
	token, _, err := mgr.GenerateAccessToken("user-x")
	require.NoError(t, err)

	_, err = mgr.ValidateAccessToken(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse access token")
}

func TestValidateAccessToken_NonHMACMethod(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaToken := jwt.New(jwt.SigningMethodRS256)
	tokenStr, err := rsaToken.SignedString(rsaKey)
	require.NoError(t, err)

	mgr := auth.NewManager("test-secret-32-bytes-long-at-min", 15*time.Minute, 30*24*time.Hour)
	_, err = mgr.ValidateAccessToken(tokenStr)
	require.Error(t, err)
}

func TestGenerateRefreshToken(t *testing.T) {
	t.Parallel()

	raw1, hash1, err := auth.GenerateRefreshToken()
	require.NoError(t, err)
	assert.NotEmpty(t, raw1)
	assert.NotEmpty(t, hash1)

	raw2, hash2, err := auth.GenerateRefreshToken()
	require.NoError(t, err)

	assert.NotEqual(t, raw1, raw2, "each call should produce a unique token")
	assert.NotEqual(t, hash1, hash2, "each call should produce a unique hash")

	t.Run("HashRefreshToken matches GenerateRefreshToken hash", func(t *testing.T) {
		hash, err := auth.HashRefreshToken(raw1)
		require.NoError(t, err)
		assert.Equal(t, hash1, hash)
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		_, err := auth.HashRefreshToken("not-base64!!!")
		require.Error(t, err)
	})
}
