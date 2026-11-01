package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// SecretRepository defines persistence operations for encrypted secrets.
type SecretRepository interface {
	// Create inserts a new secret; the server assigns the version.
	Create(ctx context.Context, secret *model.Secret) error
	// GetByID returns a secret by its UUID scoped to the user (includes deleted).
	GetByID(ctx context.Context, userID, id string) (*model.Secret, error)
	// Update replaces name and payload using optimistic concurrency control.
	// Returns *errs.ConflictError if version != baseVersion.
	Update(ctx context.Context, secret *model.Secret, baseVersion int64) error
	// Delete soft-deletes a secret using optimistic concurrency control.
	// Returns *errs.ConflictError if version != baseVersion.
	Delete(ctx context.Context, userID, id string, baseVersion int64) error
	// ListByUserID returns all non-deleted secrets for a user.
	ListByUserID(ctx context.Context, userID string) ([]*model.Secret, error)
	// ListChangedSince returns all secrets (including deleted) with version > sinceVersion.
	ListChangedSince(ctx context.Context, userID string, sinceVersion int64) ([]*model.Secret, error)
	// MaxVersion returns the highest version number among all secrets for the user (0 if none).
	MaxVersion(ctx context.Context, userID string) (int64, error)
}

type secretRepo struct {
	pool *pgxpool.Pool
}

// NewSecretRepo creates a pgx-backed SecretRepository.
func NewSecretRepo(pool *pgxpool.Pool) SecretRepository {
	return &secretRepo{pool: pool}
}

func (r *secretRepo) Create(ctx context.Context, s *model.Secret) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO secrets (id, user_id, type, name, payload, version, deleted, updated_at)
		 VALUES ($1, $2, $3, $4, $5, nextval('version_seq'), false, now())`,
		s.ID, s.UserID, string(s.Type), s.Name, s.Payload,
	)
	if err != nil {
		return fmt.Errorf("create secret: %w", err)
	}
	return nil
}

func (r *secretRepo) GetByID(ctx context.Context, userID, id string) (*model.Secret, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, user_id, type, name, payload, version, deleted, updated_at
		 FROM secrets WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	s, err := scanSecret(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return s, nil
}

func (r *secretRepo) Update(ctx context.Context, s *model.Secret, baseVersion int64) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE secrets
		 SET name = $1, payload = $2, version = nextval('version_seq'), updated_at = now()
		 WHERE id = $3 AND user_id = $4 AND version = $5 AND deleted = false`,
		s.Name, s.Payload, s.ID, s.UserID, baseVersion,
	)
	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		current, findErr := r.GetByID(ctx, s.UserID, s.ID)
		if findErr != nil {
			return findErr
		}
		return &errs.ConflictError{CurrentVersion: current.Version}
	}
	return nil
}

func (r *secretRepo) Delete(ctx context.Context, userID, id string, baseVersion int64) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE secrets
		 SET deleted = true, version = nextval('version_seq'), updated_at = now()
		 WHERE id = $1 AND user_id = $2 AND version = $3 AND deleted = false`,
		id, userID, baseVersion,
	)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		current, findErr := r.GetByID(ctx, userID, id)
		if findErr != nil {
			return findErr
		}
		if current.Deleted {
			return errs.ErrNotFound
		}
		return &errs.ConflictError{CurrentVersion: current.Version}
	}
	return nil
}

func (r *secretRepo) ListByUserID(ctx context.Context, userID string) ([]*model.Secret, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, type, name, payload, version, deleted, updated_at
		 FROM secrets WHERE user_id = $1 AND deleted = false
		 ORDER BY updated_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()
	return collectSecrets(rows)
}

func (r *secretRepo) ListChangedSince(ctx context.Context, userID string, sinceVersion int64) ([]*model.Secret, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, type, name, payload, version, deleted, updated_at
		 FROM secrets WHERE user_id = $1 AND version > $2
		 ORDER BY version ASC`,
		userID, sinceVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("list changed secrets: %w", err)
	}
	defer rows.Close()
	return collectSecrets(rows)
}

type pgxScanner interface {
	Scan(dest ...any) error
}

func scanSecret(row pgxScanner) (*model.Secret, error) {
	var s model.Secret
	var sType string
	if err := row.Scan(&s.ID, &s.UserID, &sType, &s.Name, &s.Payload, &s.Version, &s.Deleted, &s.UpdatedAt); err != nil {
		return nil, err
	}
	s.Type = model.SecretType(sType)
	return &s, nil
}

func (r *secretRepo) MaxVersion(ctx context.Context, userID string) (int64, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_id = $1`, userID,
	)
	var v int64
	if err := row.Scan(&v); err != nil {
		return 0, fmt.Errorf("max version: %w", err)
	}
	return v, nil
}

func collectSecrets(rows pgx.Rows) ([]*model.Secret, error) {
	var result []*model.Secret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		result = append(result, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secrets: %w", err)
	}
	return result, nil
}
