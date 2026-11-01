package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
)

func TestHashAndVerifyAuthKey(t *testing.T) {
	t.Parallel()

	key := []byte("super-secret-auth-key")

	hash, err := auth.HashAuthKey(key)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$argon2id$")

	t.Run("correct key matches", func(t *testing.T) {
		ok, err := auth.VerifyAuthKey(key, hash)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("wrong key does not match", func(t *testing.T) {
		ok, err := auth.VerifyAuthKey([]byte("wrong-key"), hash)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("two hashes of same key are different (random salt)", func(t *testing.T) {
		hash2, err := auth.HashAuthKey(key)
		require.NoError(t, err)
		assert.NotEqual(t, hash, hash2)

		ok, err := auth.VerifyAuthKey(key, hash2)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("invalid hash format returns error", func(t *testing.T) {
		_, err := auth.VerifyAuthKey(key, "not-a-valid-hash")
		require.Error(t, err)
	})
}
