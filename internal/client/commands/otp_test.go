package commands

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

func TestOtpDigits(t *testing.T) {
	t.Parallel()

	assert.Equal(t, otp.DigitsSix, otpDigits(6))
	assert.Equal(t, otp.DigitsEight, otpDigits(8))
	assert.Equal(t, otp.DigitsSix, otpDigits(0))
	assert.Equal(t, otp.DigitsSix, otpDigits(7))
}

func TestOtpAlgorithm(t *testing.T) {
	t.Parallel()

	assert.Equal(t, otp.AlgorithmSHA256, otpAlgorithm("SHA256"))
	assert.Equal(t, otp.AlgorithmSHA512, otpAlgorithm("SHA512"))
	assert.Equal(t, otp.AlgorithmSHA1, otpAlgorithm("SHA1"))
	assert.Equal(t, otp.AlgorithmSHA1, otpAlgorithm(""))
	assert.Equal(t, otp.AlgorithmSHA1, otpAlgorithm("unknown"))
}

func TestRunOtp_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "otp", "some-name"})
	require.Error(t, root.Execute())
}

func TestRunOtp_SecretNotFound(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "otp", "no-such-secret"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in local cache")
}

func TestRunOtp_WrongType(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	require.NoError(t, storage.NewSecretStore(db).Upsert(context.Background(), &storage.LocalSecret{
		ID:        "text-sec-1",
		Type:      model.SecretTypeText,
		Name:      "not-otp",
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Now(),
	}))
	db.Close()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "otp", "not-otp"})
	err = root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not of type otp")
}

func TestRunOtp_PasswordFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	require.NoError(t, storage.NewSecretStore(db).Upsert(context.Background(), &storage.LocalSecret{
		ID:        "otp-sec-1",
		Type:      model.SecretTypeOTP,
		Name:      "github-2fa",
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Now(),
	}))
	db.Close()

	restore := replaceStdin(t, "") // non-TTY → ReadPassword fails
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "otp", "github-2fa"})
	err = root.Execute()
	require.Error(t, err)
}
