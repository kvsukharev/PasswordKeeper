package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// PendingChange is a local modification queued for the next sync.
type PendingChange struct {
	ID          string
	Action      string // "create", "update", "delete"
	Type        model.SecretType
	Name        string
	Payload     []byte
	BaseVersion int64
	QueuedAt    time.Time
}

// PendingStore manages the pending_changes table.
type PendingStore struct {
	db *sql.DB
}

// NewPendingStore creates a PendingStore backed by db.
func NewPendingStore(db *sql.DB) *PendingStore {
	return &PendingStore{db: db}
}

// Enqueue adds a change to the pending queue.
func (s *PendingStore) Enqueue(ctx context.Context, ch *PendingChange) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pending_changes (id, action, type, name, payload, base_version, queued_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ch.ID, ch.Action, string(ch.Type), ch.Name, ch.Payload,
		ch.BaseVersion, time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("enqueue pending change: %w", err)
	}
	return nil
}

// List returns all pending changes ordered by queued_at ascending.
func (s *PendingStore) List(ctx context.Context) ([]*PendingChange, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, action, type, name, payload, base_version, queued_at
		 FROM pending_changes ORDER BY queued_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list pending changes: %w", err)
	}
	defer rows.Close()

	var result []*PendingChange
	for rows.Next() {
		ch, scanErr := scanPendingChange(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan pending change: %w", scanErr)
		}
		result = append(result, ch)
	}
	return result, rows.Err()
}

// Clear removes all pending changes.
func (s *PendingStore) Clear(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending_changes`)
	if err != nil {
		return fmt.Errorf("clear pending changes: %w", err)
	}
	return nil
}

func scanPendingChange(rows *sql.Rows) (*PendingChange, error) {
	var ch PendingChange
	var sType, queuedAt string
	if err := rows.Scan(&ch.ID, &ch.Action, &sType, &ch.Name, &ch.Payload, &ch.BaseVersion, &queuedAt); err != nil {
		return nil, err
	}
	ch.Type = model.SecretType(sType)
	ch.QueuedAt, _ = time.Parse(time.RFC3339Nano, queuedAt)
	return &ch, nil
}
