package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
)

func makeKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	key := makeKey()
	plaintext := []byte("secret payload content")
	aad := crypto.MakeAAD("secret-uuid-1", "credentials")

	ciphertext, err := crypto.Encrypt(key, plaintext, aad)
	require.NoError(t, err)
	assert.Greater(t, len(ciphertext), len(plaintext), "ciphertext should be longer (nonce+tag overhead)")

	t.Run("round-trip", func(t *testing.T) {
		got, err := crypto.Decrypt(key, ciphertext, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	})

	t.Run("two encryptions produce different ciphertexts (random nonce)", func(t *testing.T) {
		ct2, err := crypto.Encrypt(key, plaintext, aad)
		require.NoError(t, err)
		assert.NotEqual(t, ciphertext, ct2)

		got, err := crypto.Decrypt(key, ct2, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	})

	t.Run("wrong key fails", func(t *testing.T) {
		wrongKey := make([]byte, 32)
		_, err := crypto.Decrypt(wrongKey, ciphertext, aad)
		require.Error(t, err)
	})

	t.Run("tampered ciphertext fails", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)-1] ^= 0xFF
		_, err := crypto.Decrypt(key, tampered, aad)
		require.Error(t, err)
	})

	t.Run("wrong AAD fails (binding protection)", func(t *testing.T) {
		wrongAAD := crypto.MakeAAD("other-id", "text")
		_, err := crypto.Decrypt(key, ciphertext, wrongAAD)
		require.Error(t, err)
	})

	t.Run("truncated ciphertext fails", func(t *testing.T) {
		_, err := crypto.Decrypt(key, ciphertext[:5], aad)
		require.Error(t, err)
	})
}

func TestMakeAAD(t *testing.T) {
	t.Parallel()

	aad := crypto.MakeAAD("id-1", "credentials")
	assert.Equal(t, []byte("id-1:credentials"), aad)
}
