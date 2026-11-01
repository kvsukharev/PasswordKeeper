package service

import (
	"context"

	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// SyncService coordinates version-based synchronisation between clients.
type SyncService interface {
	// Pull returns all secrets changed after sinceVersion and the current max version.
	Pull(ctx context.Context, userID string, sinceVersion int64) ([]*model.Secret, int64, error)
	// Push applies local changes; conflicts are returned instead of erroring.
	Push(ctx context.Context, userID string, changes []*model.SecretChange) ([]*model.ChangeResult, []*model.ConflictInfo, error)
}
