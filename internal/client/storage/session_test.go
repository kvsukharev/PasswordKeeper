package storage_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

func openTestDB(t *testing.T) *storage.SessionStore {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(dir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return storage.NewSessionStore(db)
}

func TestSessionStore_SaveAndLoad(t *testing.T) {
	t.Parallel()

	store := openTestDB(t)
	ctx := context.Background()

	sess := &storage.Session{
		Login:        "alice",
		AccessToken:  "access-tok",
		RefreshToken: "refresh-tok",
		ExpiresAt:    time.Now().UTC().Truncate(time.Second).Add(15 * time.Minute),
	}

	require.NoError(t, store.Save(ctx, sess))

	got, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, sess.Login, got.Login)
	assert.Equal(t, sess.AccessToken, got.AccessToken)
	assert.Equal(t, sess.RefreshToken, got.RefreshToken)
	assert.Equal(t, sess.ExpiresAt.Unix(), got.ExpiresAt.Unix())
}

func TestSessionStore_LoadNoSession(t *testing.T) {
	t.Parallel()

	store := openTestDB(t)
	_, err := store.Load(context.Background())
	require.ErrorIs(t, err, storage.ErrNoSession)
}

func TestSessionStore_Clear(t *testing.T) {
	t.Parallel()

	store := openTestDB(t)
	ctx := context.Background()

	sess := &storage.Session{
		Login:        "bob",
		AccessToken:  "tok",
		RefreshToken: "ref",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Save(ctx, sess))
	require.NoError(t, store.Clear(ctx))

	_, err := store.Load(ctx)
	require.ErrorIs(t, err, storage.ErrNoSession)
}

func TestSessionStore_UpdateTokens(t *testing.T) {
	t.Parallel()

	store := openTestDB(t)
	ctx := context.Background()

	sess := &storage.Session{
		Login:        "carol",
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(time.Minute),
	}
	require.NoError(t, store.Save(ctx, sess))

	newExpiry := time.Now().Add(15 * time.Minute)
	require.NoError(t, store.UpdateTokens(ctx, "new-access", "new-refresh", newExpiry))

	got, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, "carol", got.Login)
	assert.Equal(t, "new-access", got.AccessToken)
	assert.Equal(t, "new-refresh", got.RefreshToken)
}

func TestOpenDB_CreatesDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	subDir := dir + "/sub/dir"

	db, err := storage.OpenDB(subDir)
	require.NoError(t, err)
	db.Close()

	_, err = os.Stat(subDir)
	assert.NoError(t, err)
}
