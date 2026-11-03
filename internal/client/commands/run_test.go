package commands

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// prepareDB opens (or creates) the SQLite DB for the given dataDir and saves a
// test session so commands that require a session can run.
func prepareDB(t *testing.T, dataDir string) {
	t.Helper()
	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	sess := &storage.Session{
		Login:        "testuser",
		AccessToken:  "test.access.token",
		RefreshToken: "test.refresh.token",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	store := storage.NewSessionStore(db)
	require.NoError(t, store.Save(context.Background(), sess))
}

// --- runList tests ---

func TestRunList_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	// No session saved — list should return ErrNoSession.
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "list"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunList_Empty(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "list"})
	require.NoError(t, root.Execute())
}

func TestRunList_WithSecrets(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	defer db.Close()
	secrets := storage.NewSecretStore(db)
	require.NoError(t, secrets.Upsert(context.Background(), &storage.LocalSecret{
		ID:        "sec-1",
		Type:      model.SecretTypeText,
		Name:      "my note",
		Payload:   []byte("enc"),
		Version:   3,
		UpdatedAt: time.Now(),
	}))

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "list"})
	require.NoError(t, root.Execute())
}

func TestRunList_WithConflict(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	defer db.Close()
	secrets := storage.NewSecretStore(db)
	require.NoError(t, secrets.Upsert(context.Background(), &storage.LocalSecret{
		ID:         "sec-2",
		Type:       model.SecretTypeText,
		Name:       "conflicted",
		Payload:    []byte("enc"),
		Version:    1,
		IsConflict: true,
		UpdatedAt:  time.Now(),
	}))

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "list"})
	require.NoError(t, root.Execute())
}

// --- runAdd: early error paths ---

func TestRunAdd_InvalidType(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "add", "invalidtype"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunAdd_NoSession(t *testing.T) {
	// Session load fails → ErrNoSession returned before any prompts.
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "add", "text", "--name", "foo"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunAdd_SessionExists_PasswordFails(t *testing.T) {
	// Session exists but ReadPassword fails (non-TTY) after ReadLine is skipped.
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	restore := replaceStdin(t, "")
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "add", "text", "--name", "mynote"})
	err := root.Execute()
	require.Error(t, err) // ReadPassword fails on pipe
}

// --- runDelete: early error paths ---

func TestRunDelete_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "delete", "some-name"})
	err := root.Execute()
	require.Error(t, err)
}

// --- runGet: early error paths ---

func TestRunGet_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "get", "some-name"})
	err := root.Execute()
	require.Error(t, err)
}

// --- runEdit: early error paths ---

func TestRunEdit_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "edit", "some-name"})
	err := root.Execute()
	require.Error(t, err)
}

// --- runSync: early error path ---

func TestRunSync_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "sync"})
	err := root.Execute()
	require.Error(t, err)
}

// --- runDelete: offline path ---

func TestRunDelete_SecretNotFound(t *testing.T) {
	// Session exists but secret not in local cache.
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "delete", "no-such-secret", "--yes"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunDelete_OfflineFallback(t *testing.T) {
	// Session exists, secret found, --yes set, server unavailable → offline queue.
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	secrets := storage.NewSecretStore(db)
	require.NoError(t, secrets.Upsert(context.Background(), &storage.LocalSecret{
		ID:        "del-1",
		Type:      model.SecretTypeText,
		Name:      "to-delete",
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Now(),
	}))
	db.Close()

	// Use a server address that will refuse connections → codes.Unavailable.
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "--server", "localhost:1",
		"delete", "to-delete", "--yes"})
	// Offline fallback: returns nil (success) and queues the deletion.
	require.NoError(t, root.Execute())
}

// --- runDownload: early error paths ---

func TestRunDownload_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "download", "some-file"})
	require.Error(t, root.Execute())
}

func TestRunDownload_SecretNotFound(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "download", "no-such-secret"})
	require.Error(t, root.Execute())
}

func TestRunDownload_PasswordFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	secrets := storage.NewSecretStore(db)
	require.NoError(t, secrets.Upsert(context.Background(), &storage.LocalSecret{
		ID:        "dl-1",
		Type:      model.SecretTypeBinary,
		Name:      "archive.bin",
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Now(),
	}))
	db.Close()

	restore := replaceStdin(t, "")
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "download", "archive.bin"})
	require.Error(t, root.Execute()) // ReadPassword fails on pipe
}

// --- runGet: secret not found ---

func TestRunGet_SecretNotFound(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "get", "no-such-secret"})
	require.Error(t, root.Execute())
}

// --- runSync: session exists, server unavailable ---

func TestRunSync_SessionExists_ServerUnavailable(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "--server", "localhost:1", "sync"})
	require.Error(t, root.Execute()) // Pull fails with Unavailable
}

// --- runGet: password prompt fails on non-TTY ---

func TestRunGet_PasswordFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	secrets := storage.NewSecretStore(db)
	require.NoError(t, secrets.Upsert(context.Background(), &storage.LocalSecret{
		ID:        "g-1",
		Type:      model.SecretTypeText,
		Name:      "my note",
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Now(),
	}))
	db.Close()

	restore := replaceStdin(t, "")
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "get", "my note"})
	require.Error(t, root.Execute()) // ReadPassword fails on non-TTY
}

// --- runEdit: early error paths ---

func TestRunEdit_SecretNotFound(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "edit", "no-such-secret"})
	require.Error(t, root.Execute())
}

func TestRunEdit_PasswordFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	secrets := storage.NewSecretStore(db)
	require.NoError(t, secrets.Upsert(context.Background(), &storage.LocalSecret{
		ID:        "e-1",
		Type:      model.SecretTypeText,
		Name:      "editable",
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Now(),
	}))
	db.Close()

	restore := replaceStdin(t, "")
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "edit", "editable"})
	require.Error(t, root.Execute()) // ReadPassword fails on non-TTY
}

// --- runRegister: ReadLine fails on empty stdin ---

func TestRunRegister_ReadLineFails(t *testing.T) {
	restore := replaceStdin(t, "")
	defer restore()

	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "register"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunRegister_EmptyLogin(t *testing.T) {
	restore := replaceStdin(t, "\n") // empty login line
	defer restore()

	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "register"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunRegister_PasswordFails(t *testing.T) {
	restore := replaceStdin(t, "testuser\n") // valid login, then ReadPassword fails
	defer restore()

	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "register"})
	err := root.Execute()
	require.Error(t, err) // ReadPassword fails on non-TTY
}

// --- runLogin: ReadLine fails on empty stdin ---

func TestRunLogin_ReadLineFails(t *testing.T) {
	restore := replaceStdin(t, "")
	defer restore()

	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "login"})
	err := root.Execute()
	require.Error(t, err)
}

func TestRunLogin_PasswordFails(t *testing.T) {
	restore := replaceStdin(t, "alice\n") // valid login, then ReadPassword fails
	defer restore()

	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "login"})
	err := root.Execute()
	require.Error(t, err) // ReadPassword fails on non-TTY
}

func TestRunLogin_EmptyLogin(t *testing.T) {
	restore := replaceStdin(t, "\n") // empty login line
	defer restore()

	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "login"})
	err := root.Execute()
	require.Error(t, err)
}

// --- runLogout: early error paths ---

func TestRunLogout_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "logout"})
	require.Error(t, root.Execute())
}

func TestRunLogout_SessionExpired_ServerUnavailable(t *testing.T) {
	dataDir := t.TempDir()
	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	defer db.Close()
	store := storage.NewSessionStore(db)
	require.NoError(t, store.Save(context.Background(), &storage.Session{
		Login:        "testuser",
		AccessToken:  "test.access.token",
		RefreshToken: "test.refresh.token",
		ExpiresAt:    time.Now().Add(-time.Hour), // expired
	}))

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "--server", "localhost:1", "logout"})
	// Refresh fails → clears session, returns nil ("Logged out (session already expired on server)")
	require.NoError(t, root.Execute())
}

func TestRunLogout_NotExpired_LogoutFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir) // session with ExpiresAt = now+1h (not expired)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "--server", "localhost:1", "logout"})
	require.Error(t, root.Execute()) // Logout RPC fails → server logout failed error
}

// --- runUpload: early error paths ---

func TestRunUpload_NoSession(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "upload", "some-file.bin"})
	require.Error(t, root.Execute())
}

func TestRunUpload_FileNotFound(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "upload", "/nonexistent/path/missing.bin"})
	require.Error(t, root.Execute())
}

func TestRunUpload_EmptyFile(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	f, err := os.CreateTemp(t.TempDir(), "empty-*.bin")
	require.NoError(t, err)
	f.Close()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "upload", f.Name()})
	require.Error(t, root.Execute())
}

func TestRunUpload_PasswordFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	f, err := os.CreateTemp(t.TempDir(), "nonempty-*.bin")
	require.NoError(t, err)
	_, err = f.Write([]byte("content"))
	require.NoError(t, err)
	f.Close()

	restore := replaceStdin(t, "")
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "upload", f.Name()})
	require.Error(t, root.Execute()) // ReadPassword fails on pipe
}

// --- runDownload: two-arg path ---

func TestRunDownload_TwoArgs_SecretNotFound(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "download", "no-such-secret", "/tmp/output.bin"})
	require.Error(t, root.Execute())
}

// --- runSync: expired session, server unavailable ---

func TestRunSync_SessionExpired_ServerUnavailable(t *testing.T) {
	dataDir := t.TempDir()
	db, err := storage.OpenDB(dataDir)
	require.NoError(t, err)
	defer db.Close()
	store := storage.NewSessionStore(db)
	require.NoError(t, store.Save(context.Background(), &storage.Session{
		Login:        "testuser",
		AccessToken:  "test.access.token",
		RefreshToken: "test.refresh.token",
		ExpiresAt:    time.Now().Add(-time.Hour), // expired
	}))

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "--server", "localhost:1", "sync"})
	require.Error(t, root.Execute()) // refreshSessionIfNeeded fails
}

// --- runAdd: name prompt paths ---

func TestRunAdd_NameReadLineFails(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	restore := replaceStdin(t, "") // EOF immediately → ReadLine fails
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "add", "text"}) // no --name
	require.Error(t, root.Execute())
}

func TestRunAdd_EmptyName(t *testing.T) {
	dataDir := t.TempDir()
	prepareDB(t, dataDir)

	restore := replaceStdin(t, "\n") // empty name → "name is required"
	defer restore()

	root := NewRootCmd("1.0.0", "2024-01-01", "abc")
	root.SetArgs([]string{"--data-dir", dataDir, "add", "text"}) // no --name
	require.Error(t, root.Execute())
}
