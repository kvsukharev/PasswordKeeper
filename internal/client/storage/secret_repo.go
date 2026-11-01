package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// ErrSecretNotFound is returned when a local secret lookup finds no matching row.
var ErrSecretNotFound = errors.New("secret not found in local cache")

// LocalSecret is the client-side cached representation of an encrypted secret.
type LocalSecret struct {
	ID         string
	Type       model.SecretType
	Name       string
	Payload    []byte
	Version    int64
	Deleted    bool
	UpdatedAt  time.Time
	IsConflict bool
}

// SecretStore manages the local SQLite secret cache.
type SecretStore struct {
	db *sql.DB
}

// NewSecretStore creates a SecretStore backed by the given database.
func NewSecretStore(db *sql.DB) *SecretStore {
	return &SecretStore{db: db}
}

// Upsert inserts or replaces a secret entry in the local cache.
func (s *SecretStore) Upsert(ctx context.Context, sec *LocalSecret) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO secrets (id, type, name, payload, version, deleted, updated_at, is_conflict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		     name        = excluded.name,
		     payload     = excluded.payload,
		     version     = excluded.version,
		     deleted     = excluded.deleted,
		     updated_at  = excluded.updated_at,
		     is_conflict = excluded.is_conflict`,
		sec.ID, string(sec.Type), sec.Name, sec.Payload,
		sec.Version, boolToInt(sec.Deleted),
		sec.UpdatedAt.UTC().Format(time.RFC3339Nano),
		boolToInt(sec.IsConflict),
	)
	if err != nil {
		return fmt.Errorf("upsert secret: %w", err)
	}
	return nil
}

// GetByID returns a local secret by its UUID.
func (s *SecretStore) GetByID(ctx context.Context, id string) (*LocalSecret, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, type, name, payload, version, deleted, updated_at, is_conflict
		 FROM secrets WHERE id = ?`, id)
	sec, err := scanLocalSecret(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("get secret by id: %w", err)
	}
	return sec, nil
}

// GetByName returns the first non-deleted local secret with the given name.
func (s *SecretStore) GetByName(ctx context.Context, name string) (*LocalSecret, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, type, name, payload, version, deleted, updated_at, is_conflict
		 FROM secrets WHERE name = ? AND deleted = 0 LIMIT 1`, name)
	sec, err := scanLocalSecret(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("get secret by name: %w", err)
	}
	return sec, nil
}

// List returns all non-deleted local secrets ordered by name.
func (s *SecretStore) List(ctx context.Context) ([]*LocalSecret, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, name, payload, version, deleted, updated_at, is_conflict
		 FROM secrets WHERE deleted = 0 ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()

	var result []*LocalSecret
	for rows.Next() {
		sec, err := scanLocalSecretRows(rows)
		if err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		result = append(result, sec)
	}
	return result, rows.Err()
}

// SoftDelete marks a local secret as deleted without removing it from the cache.
func (s *SecretStore) SoftDelete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE secrets SET deleted = 1, updated_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), id,
	)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanLocalSecret(r rowScanner) (*LocalSecret, error) {
	var s LocalSecret
	var sType, updatedAt string
	var deleted, isConflict int
	if err := r.Scan(&s.ID, &sType, &s.Name, &s.Payload, &s.Version, &deleted, &updatedAt, &isConflict); err != nil {
		return nil, err
	}
	s.Type = model.SecretType(sType)
	s.Deleted = deleted != 0
	s.IsConflict = isConflict != 0
	s.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &s, nil
}

func scanLocalSecretRows(rows *sql.Rows) (*LocalSecret, error) {
	return scanLocalSecret(rows)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
