package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/service"
	mockstorage "github.com/kvsuharev/passwordkeeper/internal/server/storage/mock"
)

func newSecretSvc(ctrl *gomock.Controller) (service.SecretService, *mockstorage.MockSecretRepository) {
	repo := mockstorage.NewMockSecretRepository(ctrl)
	return service.NewSecretService(repo), repo
}

var testSecret = &model.Secret{
	ID:      "secret-uuid-1",
	UserID:  "user-1",
	Type:    model.SecretTypeText,
	Name:    "my note",
	Payload: []byte("encrypted"),
	Version: 5,
}

func TestSecretService_Create(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(testSecret, nil)

		got, err := svc.Create(context.Background(), "user-1", &model.Secret{
			ID:      "secret-uuid-1",
			Type:    model.SecretTypeText,
			Name:    "my note",
			Payload: []byte("encrypted"),
		})
		require.NoError(t, err)
		assert.Equal(t, int64(5), got.Version)
	})

	t.Run("missing id returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _ := newSecretSvc(ctrl)

		_, err := svc.Create(context.Background(), "user-1", &model.Secret{
			Name: "x", Payload: []byte("y"),
		})
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})

	t.Run("missing name returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _ := newSecretSvc(ctrl)

		_, err := svc.Create(context.Background(), "user-1", &model.Secret{
			ID: "x", Payload: []byte("y"),
		})
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})

	t.Run("missing payload returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _ := newSecretSvc(ctrl)

		_, err := svc.Create(context.Background(), "user-1", &model.Secret{
			ID: "x", Name: "y",
		})
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})

	t.Run("repo error is propagated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errs.ErrAlreadyExists)

		_, err := svc.Create(context.Background(), "user-1", &model.Secret{
			ID: "x", Name: "y", Payload: []byte("z"),
		})
		require.ErrorIs(t, err, errs.ErrAlreadyExists)
	})
}

func TestSecretService_Get(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(testSecret, nil)

		got, err := svc.Get(context.Background(), "user-1", "secret-uuid-1")
		require.NoError(t, err)
		assert.Equal(t, "my note", got.Name)
	})

	t.Run("deleted secret returns ErrNotFound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		deleted := *testSecret
		deleted.Deleted = true
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(&deleted, nil)

		_, err := svc.Get(context.Background(), "user-1", "secret-uuid-1")
		require.ErrorIs(t, err, errs.ErrNotFound)
	})

	t.Run("missing id returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _ := newSecretSvc(ctrl)

		_, err := svc.Get(context.Background(), "user-1", "")
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})

	t.Run("repo not found propagated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		repo.EXPECT().GetByID(gomock.Any(), "user-1", "missing").Return(nil, errs.ErrNotFound)

		_, err := svc.Get(context.Background(), "user-1", "missing")
		require.ErrorIs(t, err, errs.ErrNotFound)
	})
}

func TestSecretService_Update(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		updated := *testSecret
		updated.Version = 6
		repo.EXPECT().Update(gomock.Any(), gomock.Any(), int64(5)).Return(nil)
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(&updated, nil)

		got, err := svc.Update(context.Background(), "user-1", &model.Secret{
			ID:      "secret-uuid-1",
			Name:    "new name",
			Payload: []byte("new payload"),
		}, 5)
		require.NoError(t, err)
		assert.Equal(t, int64(6), got.Version)
	})

	t.Run("conflict is propagated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		repo.EXPECT().Update(gomock.Any(), gomock.Any(), int64(3)).Return(&errs.ConflictError{CurrentVersion: 5})

		_, err := svc.Update(context.Background(), "user-1", &model.Secret{
			ID:      "secret-uuid-1",
			Name:    "x",
			Payload: []byte("y"),
		}, 3)
		require.ErrorIs(t, err, errs.ErrAborted)
	})

	t.Run("missing id returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _ := newSecretSvc(ctrl)

		_, err := svc.Update(context.Background(), "user-1", &model.Secret{
			Name: "x", Payload: []byte("y"),
		}, 1)
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})
}

func TestSecretService_Delete(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		deletedRecord := *testSecret
		deletedRecord.Deleted = true
		repo.EXPECT().Delete(gomock.Any(), "user-1", "secret-uuid-1", int64(5)).Return(nil)
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(&deletedRecord, nil)

		got, err := svc.Delete(context.Background(), "user-1", "secret-uuid-1", 5)
		require.NoError(t, err)
		assert.True(t, got.Deleted)
	})

	t.Run("conflict is propagated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo := newSecretSvc(ctrl)

		repo.EXPECT().Delete(gomock.Any(), "user-1", "secret-uuid-1", int64(2)).Return(&errs.ConflictError{CurrentVersion: 5})

		_, err := svc.Delete(context.Background(), "user-1", "secret-uuid-1", 2)
		require.ErrorIs(t, err, errs.ErrAborted)
	})

	t.Run("missing id returns ErrInvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _ := newSecretSvc(ctrl)

		_, err := svc.Delete(context.Background(), "user-1", "", 1)
		require.ErrorIs(t, err, errs.ErrInvalidArgument)
	})
}
