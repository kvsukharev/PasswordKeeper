package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

func openTestDBRaw(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(dir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func newStores(t *testing.T) (*storage.SecretStore, *storage.PendingStore) {
	t.Helper()
	db := openTestDBRaw(t)
	return storage.NewSecretStore(db), storage.NewPendingStore(db)
}

func sampleSecret() *storage.LocalSecret {
	return &storage.LocalSecret{
		ID:        "sec-1",
		Type:      model.SecretTypeText,
		Name:      "my note",
		Payload:   []byte("encrypted"),
		Version:   3,
		Deleted:   false,
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
}

// --- SecretStore ---

func TestSecretStore_UpsertAndGetByID(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)
	ctx := context.Background()

	require.NoError(t, secrets.Upsert(ctx, sampleSecret()))

	got, err := secrets.GetByID(ctx, "sec-1")
	require.NoError(t, err)
	assert.Equal(t, "my note", got.Name)
	assert.Equal(t, int64(3), got.Version)
	assert.False(t, got.IsConflict)
}

func TestSecretStore_UpsertUpdatesExisting(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)
	ctx := context.Background()

	require.NoError(t, secrets.Upsert(ctx, sampleSecret()))

	updated := sampleSecret()
	updated.Name = "renamed"
	updated.Version = 4
	updated.IsConflict = true
	require.NoError(t, secrets.Upsert(ctx, updated))

	got, err := secrets.GetByID(ctx, "sec-1")
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)
	assert.Equal(t, int64(4), got.Version)
	assert.True(t, got.IsConflict)
}

func TestSecretStore_GetByName(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)
	ctx := context.Background()

	require.NoError(t, secrets.Upsert(ctx, sampleSecret()))

	got, err := secrets.GetByName(ctx, "my note")
	require.NoError(t, err)
	assert.Equal(t, "sec-1", got.ID)
}

func TestSecretStore_GetByName_NotFound(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)

	_, err := secrets.GetByName(context.Background(), "nonexistent")
	require.ErrorIs(t, err, storage.ErrSecretNotFound)
}

func TestSecretStore_List(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)
	ctx := context.Background()

	s1 := sampleSecret()
	s2 := &storage.LocalSecret{
		ID: "sec-2", Type: model.SecretTypeCard, Name: "credit card",
		Payload: []byte("enc2"), Version: 1, UpdatedAt: time.Now(),
	}
	require.NoError(t, secrets.Upsert(ctx, s1))
	require.NoError(t, secrets.Upsert(ctx, s2))

	items, err := secrets.List(ctx)
	require.NoError(t, err)
	assert.Len(t, items, 2)
}

func TestSecretStore_List_ExcludesDeleted(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)
	ctx := context.Background()

	require.NoError(t, secrets.Upsert(ctx, sampleSecret()))
	require.NoError(t, secrets.SoftDelete(ctx, "sec-1"))

	items, err := secrets.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestSecretStore_SoftDelete(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)
	ctx := context.Background()

	require.NoError(t, secrets.Upsert(ctx, sampleSecret()))
	require.NoError(t, secrets.SoftDelete(ctx, "sec-1"))

	got, err := secrets.GetByID(ctx, "sec-1")
	require.NoError(t, err)
	assert.True(t, got.Deleted)
}

func TestSecretStore_GetByID_NotFound(t *testing.T) {
	t.Parallel()

	secrets, _ := newStores(t)

	_, err := secrets.GetByID(context.Background(), "missing")
	require.ErrorIs(t, err, storage.ErrSecretNotFound)
}

// --- PendingStore ---

func TestPendingStore_EnqueueAndList(t *testing.T) {
	t.Parallel()

	_, pending := newStores(t)
	ctx := context.Background()

	require.NoError(t, pending.Enqueue(ctx, &storage.PendingChange{
		ID:     "sec-1",
		Action: "create",
		Type:   model.SecretTypeText,
		Name:   "my note",
	}))

	items, err := pending.List(ctx)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "sec-1", items[0].ID)
	assert.Equal(t, "create", items[0].Action)
	assert.Equal(t, model.SecretTypeText, items[0].Type)
}

func TestPendingStore_Clear(t *testing.T) {
	t.Parallel()

	_, pending := newStores(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, pending.Enqueue(ctx, &storage.PendingChange{
			ID:     "sec-1",
			Action: "update",
			Type:   model.SecretTypeText,
			Name:   "x",
		}))
	}

	require.NoError(t, pending.Clear(ctx))

	items, err := pending.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestPendingStore_ListOrdered(t *testing.T) {
	t.Parallel()

	_, pending := newStores(t)
	ctx := context.Background()

	for _, action := range []string{"create", "update", "delete"} {
		require.NoError(t, pending.Enqueue(ctx, &storage.PendingChange{
			ID: "sec-1", Action: action, Type: model.SecretTypeText, Name: "x",
		}))
	}

	items, err := pending.List(ctx)
	require.NoError(t, err)
	require.Len(t, items, 3)
	assert.Equal(t, "create", items[0].Action)
}

// --- SyncVersion ---

func TestSessionStore_SyncVersion(t *testing.T) {
	t.Parallel()

	db := openTestDBRaw(t)
	sess := storage.NewSessionStore(db)
	ctx := context.Background()

	// Default is 0.
	v, err := sess.GetSyncVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), v)

	require.NoError(t, sess.SetSyncVersion(ctx, 42))

	v, err = sess.GetSyncVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(42), v)

	// Manually corrupt the stored value to hit the parse error path.
	_, dbErr := db.ExecContext(ctx,
		`INSERT INTO session(key, value) VALUES('sync_version','not-a-number') ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
	require.NoError(t, dbErr)

	_, err = sess.GetSyncVersion(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse sync_version")
}

func TestSessionStore_Load_BadExpiresAt(t *testing.T) {
	t.Parallel()

	db := openTestDBRaw(t)
	ctx := context.Background()
	store := storage.NewSessionStore(db)

	// Insert all required session keys with an invalid expires_at value.
	for _, kv := range [][2]string{
		{"login", "testuser"},
		{"access_token", "tok"},
		{"refresh_token", "ref"},
		{"expires_at", "not-a-valid-timestamp"},
	} {
		_, err := db.ExecContext(ctx,
			`INSERT INTO session(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			kv[0], kv[1])
		require.NoError(t, err)
	}

	_, err := store.Load(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse expires_at")
}
