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
	mockservice "github.com/kvsuharev/passwordkeeper/internal/server/service/mock"
	mockstorage "github.com/kvsuharev/passwordkeeper/internal/server/storage/mock"
)

func newSyncSvc(ctrl *gomock.Controller) (service.SyncService, *mockstorage.MockSecretRepository, *mockservice.MockSecretService) {
	repo := mockstorage.NewMockSecretRepository(ctrl)
	secretSvc := mockservice.NewMockSecretService(ctrl)
	svc := service.NewSyncService(repo, secretSvc)
	return svc, repo, secretSvc
}

func TestSyncService_Pull(t *testing.T) {
	t.Parallel()

	t.Run("returns changed secrets and max version", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo, _ := newSyncSvc(ctrl)

		secrets := []*model.Secret{testSecret}
		repo.EXPECT().ListChangedSince(gomock.Any(), "user-1", int64(10)).Return(secrets, nil)
		repo.EXPECT().MaxVersion(gomock.Any(), "user-1").Return(int64(15), nil)

		got, ver, err := svc.Pull(context.Background(), "user-1", 10)
		require.NoError(t, err)
		assert.Equal(t, int64(15), ver)
		assert.Len(t, got, 1)
	})

	t.Run("repo error propagated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo, _ := newSyncSvc(ctrl)

		repo.EXPECT().ListChangedSince(gomock.Any(), "user-1", int64(0)).Return(nil, errs.ErrNotFound)

		_, _, err := svc.Pull(context.Background(), "user-1", 0)
		require.Error(t, err)
	})

	t.Run("max version error propagated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo, _ := newSyncSvc(ctrl)

		repo.EXPECT().ListChangedSince(gomock.Any(), "user-1", int64(0)).Return(nil, nil)
		repo.EXPECT().MaxVersion(gomock.Any(), "user-1").Return(int64(0), assert.AnError)

		_, _, err := svc.Pull(context.Background(), "user-1", 0)
		require.Error(t, err)
	})
}

func TestSyncService_Push_Create(t *testing.T) {
	t.Parallel()

	t.Run("create succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, secretSvc := newSyncSvc(ctrl)

		created := *testSecret
		created.Version = 10
		secretSvc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(&created, nil)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:  model.ChangeActionCreate,
			ID:      "secret-uuid-1",
			Type:    model.SecretTypeText,
			Name:    "my note",
			Payload: []byte("enc"),
		}})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
		require.Len(t, results, 1)
		assert.Equal(t, int64(10), results[0].NewVersion)
	})

	t.Run("already exists returns result with current version", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo, secretSvc := newSyncSvc(ctrl)

		secretSvc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(nil, errs.ErrAlreadyExists)
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(testSecret, nil)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:  model.ChangeActionCreate,
			ID:      "secret-uuid-1",
			Type:    model.SecretTypeText,
			Name:    "my note",
			Payload: []byte("enc"),
		}})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
		require.Len(t, results, 1)
		assert.Equal(t, testSecret.Version, results[0].NewVersion)
	})
}

func TestSyncService_Push_UnknownAction(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, _, _ := newSyncSvc(ctrl)

	results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeAction("unknown"),
		ID:     "x",
	}})
	require.NoError(t, err)
	assert.Empty(t, results)
	assert.Empty(t, conflicts)
}

func TestSyncService_Push_Create_NonAlreadyExistsError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, _, secretSvc := newSyncSvc(ctrl)

	secretSvc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(nil, assert.AnError)

	_, _, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeActionCreate, ID: "x", Payload: []byte("p"),
	}})
	require.Error(t, err)
}

func TestSyncService_Push_Create_GetByIDError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, repo, secretSvc := newSyncSvc(ctrl)

	secretSvc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(nil, errs.ErrAlreadyExists)
	repo.EXPECT().GetByID(gomock.Any(), "user-1", "x").Return(nil, assert.AnError)

	_, _, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeActionCreate, ID: "x", Payload: []byte("p"),
	}})
	require.Error(t, err)
}

func TestSyncService_Push_Update_NonConflictError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, _, secretSvc := newSyncSvc(ctrl)

	secretSvc.EXPECT().Update(gomock.Any(), "user-1", gomock.Any(), int64(1)).Return(nil, assert.AnError)

	_, _, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeActionUpdate, ID: "x", BaseVersion: 1, Payload: []byte("p"),
	}})
	require.Error(t, err)
}

func TestSyncService_Push_Update_ConflictGetByIDError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, repo, secretSvc := newSyncSvc(ctrl)

	secretSvc.EXPECT().Update(gomock.Any(), "user-1", gomock.Any(), int64(1)).Return(nil, &errs.ConflictError{CurrentVersion: 5})
	repo.EXPECT().GetByID(gomock.Any(), "user-1", "x").Return(nil, assert.AnError)

	_, _, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeActionUpdate, ID: "x", BaseVersion: 1, Payload: []byte("p"),
	}})
	require.Error(t, err)
}

func TestSyncService_Push_Delete_OtherError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, _, secretSvc := newSyncSvc(ctrl)

	secretSvc.EXPECT().Delete(gomock.Any(), "user-1", "x", int64(1)).Return(nil, assert.AnError)

	_, _, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeActionDelete, ID: "x", BaseVersion: 1,
	}})
	require.Error(t, err)
}

func TestSyncService_Push_Delete_ConflictGetByIDError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc, repo, secretSvc := newSyncSvc(ctrl)

	secretSvc.EXPECT().Delete(gomock.Any(), "user-1", "x", int64(1)).Return(nil, &errs.ConflictError{CurrentVersion: 5})
	repo.EXPECT().GetByID(gomock.Any(), "user-1", "x").Return(nil, assert.AnError)

	_, _, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
		Action: model.ChangeActionDelete, ID: "x", BaseVersion: 1,
	}})
	require.Error(t, err)
}

func TestSyncService_Push_Update(t *testing.T) {
	t.Parallel()

	t.Run("update succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, secretSvc := newSyncSvc(ctrl)

		updated := *testSecret
		updated.Version = 6
		secretSvc.EXPECT().Update(gomock.Any(), "user-1", gomock.Any(), int64(5)).Return(&updated, nil)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:      model.ChangeActionUpdate,
			ID:          "secret-uuid-1",
			Name:        "new name",
			Payload:     []byte("new payload"),
			BaseVersion: 5,
		}})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
		require.Len(t, results, 1)
		assert.Equal(t, int64(6), results[0].NewVersion)
	})

	t.Run("version conflict returns ConflictInfo", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo, secretSvc := newSyncSvc(ctrl)

		secretSvc.EXPECT().Update(gomock.Any(), "user-1", gomock.Any(), int64(3)).Return(nil, &errs.ConflictError{CurrentVersion: 5})
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(testSecret, nil)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:      model.ChangeActionUpdate,
			ID:          "secret-uuid-1",
			Name:        "x",
			Payload:     []byte("y"),
			BaseVersion: 3,
		}})
		require.NoError(t, err)
		assert.Empty(t, results)
		require.Len(t, conflicts, 1)
		assert.Equal(t, "secret-uuid-1", conflicts[0].ID)
		assert.NotNil(t, conflicts[0].ServerSecret)
	})
}

func TestSyncService_Push_Delete(t *testing.T) {
	t.Parallel()

	t.Run("delete succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, secretSvc := newSyncSvc(ctrl)

		deletedRecord := *testSecret
		deletedRecord.Deleted = true
		deletedRecord.Version = 7
		secretSvc.EXPECT().Delete(gomock.Any(), "user-1", "secret-uuid-1", int64(5)).Return(&deletedRecord, nil)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:      model.ChangeActionDelete,
			ID:          "secret-uuid-1",
			BaseVersion: 5,
		}})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
		require.Len(t, results, 1)
		assert.Equal(t, int64(7), results[0].NewVersion)
	})

	t.Run("already deleted returns success with version 0", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, _, secretSvc := newSyncSvc(ctrl)

		secretSvc.EXPECT().Delete(gomock.Any(), "user-1", "secret-uuid-1", int64(5)).Return(nil, errs.ErrNotFound)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:      model.ChangeActionDelete,
			ID:          "secret-uuid-1",
			BaseVersion: 5,
		}})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
		require.Len(t, results, 1)
		assert.Equal(t, int64(0), results[0].NewVersion)
	})

	t.Run("version conflict on delete returns ConflictInfo", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc, repo, secretSvc := newSyncSvc(ctrl)

		secretSvc.EXPECT().Delete(gomock.Any(), "user-1", "secret-uuid-1", int64(2)).Return(nil, &errs.ConflictError{CurrentVersion: 5})
		repo.EXPECT().GetByID(gomock.Any(), "user-1", "secret-uuid-1").Return(testSecret, nil)

		results, conflicts, err := svc.Push(context.Background(), "user-1", []*model.SecretChange{{
			Action:      model.ChangeActionDelete,
			ID:          "secret-uuid-1",
			BaseVersion: 2,
		}})
		require.NoError(t, err)
		assert.Empty(t, results)
		require.Len(t, conflicts, 1)
	})
}
