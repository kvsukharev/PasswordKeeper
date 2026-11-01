package service

import (
	"context"

	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// SecretService manages the lifecycle of encrypted secrets.
type SecretService interface {
	// Create stores a new secret for the authenticated user and returns the
	// server-assigned metadata (version, updated_at).
	Create(ctx context.Context, userID string, s *model.Secret) (*model.Secret, error)
	// Get retrieves a single secret by ID for the authenticated user.
	// Returns errs.ErrNotFound for missing or deleted secrets.
	Get(ctx context.Context, userID, id string) (*model.Secret, error)
	// Update replaces name and payload using optimistic concurrency control.
	// Returns *errs.ConflictError on version mismatch.
	Update(ctx context.Context, userID string, s *model.Secret, baseVersion int64) (*model.Secret, error)
	// Delete soft-deletes a secret using optimistic concurrency control.
	// Returns *errs.ConflictError on version mismatch.
	Delete(ctx context.Context, userID, id string, baseVersion int64) (*model.Secret, error)
}
