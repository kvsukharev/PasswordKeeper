package commands

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// replaceStdin temporarily replaces os.Stdin with a pipe whose write-end is
// pre-loaded with data. The caller must not call t.Parallel() since os.Stdin is
// a process-global variable.
func replaceStdin(t *testing.T, data string) func() {
	t.Helper()
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r

	_, err = fmt.Fprint(w, data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return func() {
		os.Stdin = origStdin
		r.Close()
	}
}

func TestReadLine_ReadsUntilNewline(t *testing.T) {
	restore := replaceStdin(t, "hello world\n")
	defer restore()

	got, err := ReadLine("Enter: ")
	require.NoError(t, err)
	assert.Equal(t, "hello world", got)
}

func TestReadLine_StripsCR(t *testing.T) {
	restore := replaceStdin(t, "windows line\r\n")
	defer restore()

	got, err := ReadLine("")
	require.NoError(t, err)
	assert.Equal(t, "windows line", got)
}

func TestReadLine_EOFReturnsError(t *testing.T) {
	restore := replaceStdin(t, "") // empty — immediate EOF without newline
	defer restore()

	_, err := ReadLine("")
	require.Error(t, err)
}

func TestReadLineWithDefault_NonEmpty(t *testing.T) {
	restore := replaceStdin(t, "custom value\n")
	defer restore()

	got, err := ReadLineWithDefault("Field: ", "default")
	require.NoError(t, err)
	assert.Equal(t, "custom value", got)
}

func TestReadLineWithDefault_EmptyUsesDefault(t *testing.T) {
	restore := replaceStdin(t, "\n")
	defer restore()

	got, err := ReadLineWithDefault("Field", "fallback")
	require.NoError(t, err)
	assert.Equal(t, "fallback", got)
}

func TestReadLineWithDefault_EmptyNoDefault(t *testing.T) {
	restore := replaceStdin(t, "\n")
	defer restore()

	got, err := ReadLineWithDefault("Field: ", "")
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

// TestReadPassword_NonTTY verifies the error path when stdin is not a terminal.
func TestReadPassword_NonTTY(t *testing.T) {
	restore := replaceStdin(t, "secret\n")
	defer restore()

	_, err := ReadPassword("Password: ")
	// term.ReadPassword fails on a non-TTY file descriptor — we just verify
	// the function wraps the error correctly.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read password")
}

// TestReadPasswordOptional_NonTTY covers the same error path for the optional variant.
func TestReadPasswordOptional_NonTTY(t *testing.T) {
	restore := replaceStdin(t, "\n")
	defer restore()

	_, err := ReadPasswordOptional("Password (optional): ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read password")
}

func TestPromptNewPayload_Text(t *testing.T) {
	restore := replaceStdin(t, "hello world\n")
	defer restore()

	payload, err := promptNewPayload(model.SecretTypeText)
	require.NoError(t, err)
	require.NotNil(t, payload.Text)
	assert.Equal(t, "hello world", payload.Text.Content)
}

func TestPromptNewPayload_Card_InvalidLuhn(t *testing.T) {
	// Fails at card number (Luhn) — only one ReadLine call needed.
	restore := replaceStdin(t, "1234567890123456\n")
	defer restore()

	_, err := promptNewPayload(model.SecretTypeCard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Luhn")
}

func TestPromptNewPayload_Credentials_PasswordError(t *testing.T) {
	// ReadPassword fails on a non-TTY, so we just get to the error path.
	restore := replaceStdin(t, "mylogin\n")
	defer restore()

	_, err := promptNewPayload(model.SecretTypeCredentials)
	require.Error(t, err) // term.ReadPassword fails on pipe
}

func TestPromptNewPayload_UnsupportedType(t *testing.T) {
	_, err := promptNewPayload(model.SecretTypeBinary)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestPromptEditPayload_Text(t *testing.T) {
	restore := replaceStdin(t, "\n") // empty → keep default
	defer restore()

	current := &model.Payload{Text: &model.TextPayload{Content: "existing content"}}
	payload, err := promptEditPayload(model.SecretTypeText, current)
	require.NoError(t, err)
	require.NotNil(t, payload.Text)
	assert.Equal(t, "existing content", payload.Text.Content)
}

func TestPromptEditPayload_Text_NewContent(t *testing.T) {
	restore := replaceStdin(t, "updated content\n")
	defer restore()

	current := &model.Payload{Text: &model.TextPayload{Content: "old"}}
	payload, err := promptEditPayload(model.SecretTypeText, current)
	require.NoError(t, err)
	require.NotNil(t, payload.Text)
	assert.Equal(t, "updated content", payload.Text.Content)
}

func TestPromptEditPayload_Default_ReturnsCurrent(t *testing.T) {
	// Binary type falls through to default → returns current unchanged, no stdin.
	current := &model.Payload{Text: &model.TextPayload{Content: "binary-ish"}}
	payload, err := promptEditPayload(model.SecretTypeBinary, current)
	require.NoError(t, err)
	assert.Equal(t, current, payload)
}

func TestPromptEditPayload_Credentials_ReadPasswordFails(t *testing.T) {
	// ReadPasswordOptional fails on non-TTY after the login line is read.
	restore := replaceStdin(t, "\n") // login defaults
	defer restore()

	current := &model.Payload{Credentials: &model.CredentialsPayload{Login: "alice"}}
	_, err := promptEditPayload(model.SecretTypeCredentials, current)
	require.Error(t, err) // term.ReadPassword fails on pipe
}

func TestPromptNewPayload_OTP_FirstLineOnly(t *testing.T) {
	// bufio.NewReader buffers the whole pipe on first read; only the first
	// ReadLine gets data, the second gets EOF — that's sufficient to exercise
	// the OTP branch entry and its error handling.
	restore := replaceStdin(t, "GitHub\n")
	defer restore()

	_, err := promptNewPayload(model.SecretTypeOTP)
	require.Error(t, err) // EOF on second ReadLine (account)
}

func TestRefreshSessionIfNeeded_NotExpired(t *testing.T) {
	sess := &storage.Session{
		AccessToken: "original-token",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	// conn and store are nil — function must return before using them.
	err := refreshSessionIfNeeded(context.Background(), nil, nil, sess)
	require.NoError(t, err)
	assert.Equal(t, "original-token", sess.AccessToken)
}
