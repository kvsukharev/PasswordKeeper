package service

import (
	"context"
	"fmt"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/storage"
)

type secretService struct {
	secrets storage.SecretRepository
}

// NewSecretService creates a SecretService backed by the given repository.
func NewSecretService(secrets storage.SecretRepository) SecretService {
	return &secretService{secrets: secrets}
}

func (s *secretService) Create(ctx context.Context, userID string, secret *model.Secret) (*model.Secret, error) {
	if secret.ID == "" || secret.Name == "" || len(secret.Payload) == 0 {
		return nil, fmt.Errorf("%w: id, name and payload are required", errs.ErrInvalidArgument)
	}
	secret.UserID = userID
	if err := s.secrets.Create(ctx, secret); err != nil {
		return nil, err
	}
	return s.secrets.GetByID(ctx, userID, secret.ID)
}

func (s *secretService) Get(ctx context.Context, userID, id string) (*model.Secret, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: id is required", errs.ErrInvalidArgument)
	}
	sec, err := s.secrets.GetByID(ctx, userID, id)
	if err != nil {
		return nil, err
	}
	if sec.Deleted {
		return nil, errs.ErrNotFound
	}
	return sec, nil
}

func (s *secretService) Update(ctx context.Context, userID string, secret *model.Secret, baseVersion int64) (*model.Secret, error) {
	if secret.ID == "" || secret.Name == "" || len(secret.Payload) == 0 {
		return nil, fmt.Errorf("%w: id, name and payload are required", errs.ErrInvalidArgument)
	}
	secret.UserID = userID
	if err := s.secrets.Update(ctx, secret, baseVersion); err != nil {
		return nil, err
	}
	return s.secrets.GetByID(ctx, userID, secret.ID)
}

func (s *secretService) Delete(ctx context.Context, userID, id string, baseVersion int64) (*model.Secret, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: id is required", errs.ErrInvalidArgument)
	}
	if err := s.secrets.Delete(ctx, userID, id, baseVersion); err != nil {
		return nil, err
	}
	return s.secrets.GetByID(ctx, userID, id)
}
