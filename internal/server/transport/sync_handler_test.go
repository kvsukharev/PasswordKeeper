package transport_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	mockservice "github.com/kvsuharev/passwordkeeper/internal/server/service/mock"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

func newSyncHandler(ctrl *gomock.Controller) (*transport.SyncHandler, *mockservice.MockSyncService) {
	svc := mockservice.NewMockSyncService(ctrl)
	return transport.NewSyncHandler(svc), svc
}

func TestSyncHandler_Pull(t *testing.T) {
	t.Parallel()

	t.Run("success returns secrets and version", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		svc.EXPECT().Pull(gomock.Any(), "user-1", int64(10)).Return([]*model.Secret{serverSecret}, int64(15), nil)

		resp, err := h.Pull(userCtx(), &pb.PullRequest{SinceVersion: 10})
		require.NoError(t, err)
		assert.Equal(t, int64(15), resp.GetCurrentVersion())
		assert.Len(t, resp.GetSecrets(), 1)
		assert.Equal(t, "secret-uuid-1", resp.GetSecrets()[0].GetMeta().GetId())
	})

	t.Run("unauthenticated returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSyncHandler(ctrl)

		_, err := h.Pull(context.Background(), &pb.PullRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("service error is mapped", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		svc.EXPECT().Pull(gomock.Any(), "user-1", int64(0)).Return(nil, int64(0), assert.AnError)

		_, err := h.Pull(userCtx(), &pb.PullRequest{})
		require.Error(t, err)
	})

	t.Run("empty pull returns empty secrets list", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		svc.EXPECT().Pull(gomock.Any(), "user-1", int64(0)).Return(nil, int64(5), nil)

		resp, err := h.Pull(userCtx(), &pb.PullRequest{SinceVersion: 0})
		require.NoError(t, err)
		assert.Equal(t, int64(5), resp.GetCurrentVersion())
		assert.Empty(t, resp.GetSecrets())
	})
}

func TestSyncHandler_Push(t *testing.T) {
	t.Parallel()

	t.Run("success with results", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		results := []*model.ChangeResult{{ID: "secret-uuid-1", NewVersion: 10}}
		svc.EXPECT().Push(gomock.Any(), "user-1", gomock.Any()).Return(results, nil, nil)

		resp, err := h.Push(userCtx(), &pb.PushRequest{
			Changes: []*pb.SecretChange{{
				Action:  pb.ChangeAction_CHANGE_ACTION_CREATE,
				Id:      "secret-uuid-1",
				Type:    pb.SecretType_SECRET_TYPE_TEXT,
				Name:    "my note",
				Payload: []byte("enc"),
			}},
		})
		require.NoError(t, err)
		require.Len(t, resp.GetResults(), 1)
		assert.Equal(t, "secret-uuid-1", resp.GetResults()[0].GetId())
		assert.Equal(t, int64(10), resp.GetResults()[0].GetNewVersion())
	})

	t.Run("conflict is returned in response", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		conflicts := []*model.ConflictInfo{{ID: "secret-uuid-1", ServerSecret: serverSecret}}
		svc.EXPECT().Push(gomock.Any(), "user-1", gomock.Any()).Return(nil, conflicts, nil)

		resp, err := h.Push(userCtx(), &pb.PushRequest{
			Changes: []*pb.SecretChange{{
				Action:      pb.ChangeAction_CHANGE_ACTION_UPDATE,
				Id:          "secret-uuid-1",
				Name:        "x",
				Payload:     []byte("y"),
				BaseVersion: 1,
			}},
		})
		require.NoError(t, err)
		assert.Empty(t, resp.GetResults())
		require.Len(t, resp.GetConflicts(), 1)
		assert.Equal(t, "secret-uuid-1", resp.GetConflicts()[0].GetId())
	})

	t.Run("unknown action returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSyncHandler(ctrl)

		_, err := h.Push(userCtx(), &pb.PushRequest{
			Changes: []*pb.SecretChange{{
				Action: pb.ChangeAction_CHANGE_ACTION_UNSPECIFIED,
				Id:     "x",
			}},
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("unauthenticated returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSyncHandler(ctrl)

		_, err := h.Push(context.Background(), &pb.PushRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("service error is mapped", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		svc.EXPECT().Push(gomock.Any(), "user-1", gomock.Any()).Return(nil, nil, assert.AnError)

		_, err := h.Push(userCtx(), &pb.PushRequest{
			Changes: []*pb.SecretChange{{
				Action:  pb.ChangeAction_CHANGE_ACTION_CREATE,
				Id:      "x",
				Payload: []byte("p"),
			}},
		})
		require.Error(t, err)
	})

	t.Run("delete action is handled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSyncHandler(ctrl)

		svc.EXPECT().Push(gomock.Any(), "user-1", gomock.Any()).Return(
			[]*model.ChangeResult{{ID: "x", NewVersion: 2}}, nil, nil,
		)

		resp, err := h.Push(userCtx(), &pb.PushRequest{
			Changes: []*pb.SecretChange{{
				Action:      pb.ChangeAction_CHANGE_ACTION_DELETE,
				Id:          "x",
				BaseVersion: 1,
			}},
		})
		require.NoError(t, err)
		require.Len(t, resp.GetResults(), 1)
	})
}
