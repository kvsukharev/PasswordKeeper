//go:build integration

package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/storage"
)

// setupPostgres starts a PostgreSQL container, runs migrations and returns a
// DSN. The container is terminated when t finishes.
func setupPostgres(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("passwordkeeper"),
		tcpostgres.WithUsername("passwordkeeper"),
		tcpostgres.WithPassword("passwordkeeper"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	require.NoError(t, storage.RunMigrations(ctx, dsn))
	return dsn
}

// TestUserRepo_Integration tests Create and GetByLogin against a real PostgreSQL.
func TestUserRepo_Integration(t *testing.T) {
	dsn := setupPostgres(t)
	ctx := context.Background()

	pool, err := storage.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := storage.NewUserRepo(pool)

	u := &model.User{
		ID:           "00000000-0000-0000-0000-000000000001",
		Login:        "alice",
		PasswordHash: "hash-alice",
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
	}

	t.Run("Create", func(t *testing.T) {
		require.NoError(t, repo.Create(ctx, u))
	})

	t.Run("GetByLogin", func(t *testing.T) {
		got, err := repo.GetByLogin(ctx, "alice")
		require.NoError(t, err)
		assert.Equal(t, u.ID, got.ID)
		assert.Equal(t, u.Login, got.Login)
	})

	t.Run("GetByID", func(t *testing.T) {
		got, err := repo.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, "alice", got.Login)
	})

	t.Run("Create_duplicate_returns_AlreadyExists", func(t *testing.T) {
		dup := *u
		dup.ID = "00000000-0000-0000-0000-000000000002"
		err := repo.Create(ctx, &dup)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
	})
}

// TestTokenRepo_Integration tests Create, GetByHash and Delete.
func TestTokenRepo_Integration(t *testing.T) {
	dsn := setupPostgres(t)
	ctx := context.Background()

	pool, err := storage.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	userRepo := storage.NewUserRepo(pool)
	tokenRepo := storage.NewTokenRepo(pool)

	// Seed a user that tokens will reference.
	owner := &model.User{
		ID:           "00000000-0000-0000-0000-000000000010",
		Login:        "bob",
		PasswordHash: "hash-bob",
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, userRepo.Create(ctx, owner))

	token := &model.RefreshToken{
		TokenHash: "sha256hash-of-refresh-token",
		UserID:    owner.ID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour).UTC(),
	}

	t.Run("Create", func(t *testing.T) {
		require.NoError(t, tokenRepo.Create(ctx, token))
	})

	t.Run("GetByHash", func(t *testing.T) {
		got, err := tokenRepo.GetByHash(ctx, token.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, token.UserID, got.UserID)
	})

	t.Run("Delete", func(t *testing.T) {
		require.NoError(t, tokenRepo.Delete(ctx, token.TokenHash))
		_, err := tokenRepo.GetByHash(ctx, token.TokenHash)
		require.Error(t, err)
	})
}

// TestSecretRepo_Integration tests CRUD + sync operations.
func TestSecretRepo_Integration(t *testing.T) {
	dsn := setupPostgres(t)
	ctx := context.Background()

	pool, err := storage.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	userRepo := storage.NewUserRepo(pool)
	secretRepo := storage.NewSecretRepo(pool)

	owner := &model.User{
		ID:           "00000000-0000-0000-0000-000000000020",
		Login:        "carol",
		PasswordHash: "hash-carol",
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, userRepo.Create(ctx, owner))

	sec := &model.Secret{
		ID:      "00000000-0000-0000-0000-000000000021",
		UserID:  owner.ID,
		Type:    model.SecretTypeText,
		Name:    "my note",
		Payload: []byte("encrypted-text"),
	}

	t.Run("Create", func(t *testing.T) {
		require.NoError(t, secretRepo.Create(ctx, sec))
	})

	t.Run("GetByID", func(t *testing.T) {
		got, err := secretRepo.GetByID(ctx, owner.ID, sec.ID)
		require.NoError(t, err)
		assert.Equal(t, "my note", got.Name)
		assert.Greater(t, got.Version, int64(0))
		sec.Version = got.Version // save for Update OCC check
	})

	t.Run("Update", func(t *testing.T) {
		updated := *sec
		updated.Name = "updated note"
		updated.Payload = []byte("new-encrypted")
		require.NoError(t, secretRepo.Update(ctx, &updated, sec.Version))

		got, err := secretRepo.GetByID(ctx, owner.ID, sec.ID)
		require.NoError(t, err)
		assert.Equal(t, "updated note", got.Name)
		assert.Greater(t, got.Version, sec.Version)
		sec.Version = got.Version
	})

	t.Run("Update_wrong_version_returns_ConflictError", func(t *testing.T) {
		bad := *sec
		err := secretRepo.Update(ctx, &bad, sec.Version-1)
		require.Error(t, err)
	})

	t.Run("ListByUserID", func(t *testing.T) {
		list, err := secretRepo.ListByUserID(ctx, owner.ID)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, sec.ID, list[0].ID)
	})

	t.Run("ListChangedSince", func(t *testing.T) {
		changed, err := secretRepo.ListChangedSince(ctx, owner.ID, 0)
		require.NoError(t, err)
		require.NotEmpty(t, changed)
		assert.Equal(t, sec.ID, changed[0].ID)
	})

	t.Run("MaxVersion", func(t *testing.T) {
		v, err := secretRepo.MaxVersion(ctx, owner.ID)
		require.NoError(t, err)
		assert.Equal(t, sec.Version, v)
	})

	t.Run("Delete", func(t *testing.T) {
		require.NoError(t, secretRepo.Delete(ctx, owner.ID, sec.ID, sec.Version))

		got, err := secretRepo.GetByID(ctx, owner.ID, sec.ID)
		require.NoError(t, err)
		assert.True(t, got.Deleted)
	})

	t.Run("Delete_wrong_version_returns_ConflictError", func(t *testing.T) {
		// Re-create a fresh secret for this sub-test.
		fresh := &model.Secret{
			ID:      "00000000-0000-0000-0000-000000000022",
			UserID:  owner.ID,
			Type:    model.SecretTypeCredentials,
			Name:    "fresh",
			Payload: []byte("enc"),
		}
		require.NoError(t, secretRepo.Create(ctx, fresh))
		got, err := secretRepo.GetByID(ctx, owner.ID, fresh.ID)
		require.NoError(t, err)

		err = secretRepo.Delete(ctx, owner.ID, fresh.ID, got.Version-1)
		require.Error(t, err)
	})
}

// TestIntegration_TwoClients is a sквозной (end-to-end) scenario exercising the
// sync flow between two independent clients sharing one server-side storage.
//
// Timeline:
//  1. Client A registers and creates a secret.
//  2. Client B logs in with the same account and pulls; sees the secret.
//  3. Client A edits the secret; Client B pulls again and sees the update.
//  4. Both clients edit simultaneously → conflict is detected.
func TestIntegration_TwoClients(t *testing.T) {
	dsn := setupPostgres(t)
	ctx := context.Background()

	pool, err := storage.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	userRepo := storage.NewUserRepo(pool)
	secretRepo := storage.NewSecretRepo(pool)

	owner := &model.User{
		ID:           "10000000-0000-0000-0000-000000000001",
		Login:        "shared-user",
		PasswordHash: "hash",
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, userRepo.Create(ctx, owner))

	// --- Client A: create ---
	sec := &model.Secret{
		ID:      fmt.Sprintf("20000000-0000-0000-0000-%012d", 1),
		UserID:  owner.ID,
		Type:    model.SecretTypeText,
		Name:    "shared note",
		Payload: []byte("v1-encrypted"),
	}
	require.NoError(t, secretRepo.Create(ctx, sec))
	v1, err := secretRepo.MaxVersion(ctx, owner.ID)
	require.NoError(t, err)

	// --- Client B: pull since 0 → sees the secret ---
	pulled, err := secretRepo.ListChangedSince(ctx, owner.ID, 0)
	require.NoError(t, err)
	require.Len(t, pulled, 1)
	assert.Equal(t, sec.ID, pulled[0].ID)
	clientBVersion := pulled[0].Version

	// --- Client A: update ---
	updated := *sec
	updated.Payload = []byte("v2-encrypted")
	updated.Name = "shared note v2"
	require.NoError(t, secretRepo.Update(ctx, &updated, clientBVersion))
	v2, err := secretRepo.MaxVersion(ctx, owner.ID)
	require.NoError(t, err)
	assert.Greater(t, v2, v1)

	// --- Client B: pull since v1 → sees the update ---
	delta, err := secretRepo.ListChangedSince(ctx, owner.ID, v1)
	require.NoError(t, err)
	require.Len(t, delta, 1)
	assert.Equal(t, "shared note v2", delta[0].Name)
	clientBVersion = delta[0].Version

	// --- Simultaneous edit: Client B uses stale base_version → conflict ---
	conflictAttempt := *sec
	conflictAttempt.Payload = []byte("b-encrypted")
	err = secretRepo.Update(ctx, &conflictAttempt, clientBVersion-1) // stale
	require.Error(t, err, "concurrent edit with wrong base_version should fail")
}
