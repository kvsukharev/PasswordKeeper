package service

import (
	"context"
	"errors"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/storage"
)

type syncService struct {
	secrets    storage.SecretRepository
	secretsSvc SecretService
}

// NewSyncService creates a SyncService backed by the given repository and SecretService.
func NewSyncService(secrets storage.SecretRepository, secretsSvc SecretService) SyncService {
	return &syncService{secrets: secrets, secretsSvc: secretsSvc}
}

func (s *syncService) Pull(ctx context.Context, userID string, sinceVersion int64) ([]*model.Secret, int64, error) {
	changed, err := s.secrets.ListChangedSince(ctx, userID, sinceVersion)
	if err != nil {
		return nil, 0, err
	}
	maxVer, err := s.secrets.MaxVersion(ctx, userID)
	if err != nil {
		return nil, 0, err
	}
	return changed, maxVer, nil
}

func (s *syncService) Push(ctx context.Context, userID string, changes []*model.SecretChange) ([]*model.ChangeResult, []*model.ConflictInfo, error) {
	var results []*model.ChangeResult
	var conflicts []*model.ConflictInfo

	for _, ch := range changes {
		r, c, err := s.applyChange(ctx, userID, ch)
		if err != nil {
			return nil, nil, err
		}
		if r != nil {
			results = append(results, r)
		}
		if c != nil {
			conflicts = append(conflicts, c)
		}
	}
	return results, conflicts, nil
}

func (s *syncService) applyChange(ctx context.Context, userID string, ch *model.SecretChange) (*model.ChangeResult, *model.ConflictInfo, error) {
	switch ch.Action {
	case model.ChangeActionCreate:
		created, err := s.secretsSvc.Create(ctx, userID, &model.Secret{
			ID:      ch.ID,
			Type:    ch.Type,
			Name:    ch.Name,
			Payload: ch.Payload,
		})
		if err != nil {
			if errors.Is(err, errs.ErrAlreadyExists) {
				existing, getErr := s.secrets.GetByID(ctx, userID, ch.ID)
				if getErr != nil {
					return nil, nil, getErr
				}
				return &model.ChangeResult{ID: ch.ID, NewVersion: existing.Version}, nil, nil
			}
			return nil, nil, err
		}
		return &model.ChangeResult{ID: created.ID, NewVersion: created.Version}, nil, nil

	case model.ChangeActionUpdate:
		updated, err := s.secretsSvc.Update(ctx, userID, &model.Secret{
			ID:      ch.ID,
			Name:    ch.Name,
			Payload: ch.Payload,
		}, ch.BaseVersion)
		if err != nil {
			if errors.Is(err, errs.ErrAborted) {
				server, getErr := s.secrets.GetByID(ctx, userID, ch.ID)
				if getErr != nil {
					return nil, nil, getErr
				}
				return nil, &model.ConflictInfo{ID: ch.ID, ServerSecret: server}, nil
			}
			return nil, nil, err
		}
		return &model.ChangeResult{ID: updated.ID, NewVersion: updated.Version}, nil, nil

	case model.ChangeActionDelete:
		deleted, err := s.secretsSvc.Delete(ctx, userID, ch.ID, ch.BaseVersion)
		if err != nil {
			if errors.Is(err, errs.ErrNotFound) {
				return &model.ChangeResult{ID: ch.ID, NewVersion: 0}, nil, nil
			}
			if errors.Is(err, errs.ErrAborted) {
				server, getErr := s.secrets.GetByID(ctx, userID, ch.ID)
				if getErr != nil {
					return nil, nil, getErr
				}
				return nil, &model.ConflictInfo{ID: ch.ID, ServerSecret: server}, nil
			}
			return nil, nil, err
		}
		return &model.ChangeResult{ID: ch.ID, NewVersion: deleted.Version}, nil, nil

	default:
		return nil, nil, nil
	}
}
