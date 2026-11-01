package crypto_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
)

func TestDeriveAuthKey(t *testing.T) {
	t.Parallel()

	password := []byte("master-password")
	login := "alice"

	key := crypto.DeriveAuthKey(password, login)
	require.Len(t, key, 32, "key must be 32 bytes")

	t.Run("deterministic for same inputs", func(t *testing.T) {
		key2 := crypto.DeriveAuthKey(password, login)
		assert.Equal(t, key, key2)
	})

	t.Run("different login produces different key", func(t *testing.T) {
		other := crypto.DeriveAuthKey(password, "bob")
		assert.NotEqual(t, key, other)
	})

	t.Run("different password produces different key", func(t *testing.T) {
		other := crypto.DeriveAuthKey([]byte("other-password"), login)
		assert.NotEqual(t, key, other)
	})
}

func TestDeriveEncKey(t *testing.T) {
	t.Parallel()

	password := []byte("master-password")
	login := "alice"

	encKey := crypto.DeriveEncKey(password, login)
	authKey := crypto.DeriveAuthKey(password, login)

	require.Len(t, encKey, 32)
	assert.False(t, bytes.Equal(authKey, encKey), "auth and enc keys must differ")

	t.Run("deterministic", func(t *testing.T) {
		assert.Equal(t, encKey, crypto.DeriveEncKey(password, login))
	})
}
