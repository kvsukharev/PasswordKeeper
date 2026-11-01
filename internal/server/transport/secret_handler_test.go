package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	mockservice "github.com/kvsuharev/passwordkeeper/internal/server/service/mock"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

func userCtx() context.Context {
	return transport.ContextWithUserID(context.Background(), "user-1")
}

func newSecretHandler(ctrl *gomock.Controller) (*transport.SecretHandler, *mockservice.MockSecretService) {
	svc := mockservice.NewMockSecretService(ctrl)
	return transport.NewSecretHandler(svc, 10*1024*1024), svc
}

var serverSecret = &model.Secret{
	ID:        "secret-uuid-1",
	UserID:    "user-1",
	Type:      model.SecretTypeText,
	Name:      "my note",
	Payload:   []byte("encrypted-payload"),
	Version:   5,
	UpdatedAt: time.Now(),
}

func TestSecretHandler_Create(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		svc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(serverSecret, nil)

		resp, err := h.Create(userCtx(), &pb.CreateSecretRequest{
			Id:      "secret-uuid-1",
			Type:    pb.SecretType_SECRET_TYPE_TEXT,
			Name:    "my note",
			Payload: []byte("encrypted-payload"),
		})
		require.NoError(t, err)
		assert.Equal(t, "secret-uuid-1", resp.GetId())
		assert.Equal(t, int64(5), resp.GetVersion())
	})

	t.Run("missing id returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Create(userCtx(), &pb.CreateSecretRequest{
			Name: "x", Payload: []byte("y"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("missing name returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Create(userCtx(), &pb.CreateSecretRequest{
			Id: "x", Payload: []byte("y"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("unauthenticated returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Create(context.Background(), &pb.CreateSecretRequest{
			Id: "x", Name: "y", Payload: []byte("z"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("service error returns Internal", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		svc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(nil, assert.AnError)

		_, err := h.Create(userCtx(), &pb.CreateSecretRequest{
			Id: "x", Name: "y", Payload: []byte("z"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestSecretHandler_Get(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		svc.EXPECT().Get(gomock.Any(), "user-1", "secret-uuid-1").Return(serverSecret, nil)

		resp, err := h.Get(userCtx(), &pb.GetSecretRequest{Id: "secret-uuid-1"})
		require.NoError(t, err)
		assert.Equal(t, []byte("encrypted-payload"), resp.GetPayload())
	})

	t.Run("empty id returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Get(userCtx(), &pb.GetSecretRequest{Id: ""})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("not found returns NotFound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		svc.EXPECT().Get(gomock.Any(), "user-1", "missing").Return(nil, errs.ErrNotFound)

		_, err := h.Get(userCtx(), &pb.GetSecretRequest{Id: "missing"})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("unauthenticated returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Get(context.Background(), &pb.GetSecretRequest{Id: "x"})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestSecretHandler_Update(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		updated := *serverSecret
		updated.Version = 6
		svc.EXPECT().Update(gomock.Any(), "user-1", gomock.Any(), int64(5)).Return(&updated, nil)

		resp, err := h.Update(userCtx(), &pb.UpdateSecretRequest{
			Id:          "secret-uuid-1",
			Name:        "new name",
			Payload:     []byte("new payload"),
			BaseVersion: 5,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(6), resp.GetVersion())
	})

	t.Run("version conflict returns Aborted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		svc.EXPECT().Update(gomock.Any(), "user-1", gomock.Any(), int64(1)).Return(nil, &errs.ConflictError{CurrentVersion: 5})

		_, err := h.Update(userCtx(), &pb.UpdateSecretRequest{
			Id:          "secret-uuid-1",
			Name:        "x",
			Payload:     []byte("y"),
			BaseVersion: 1,
		})
		require.Error(t, err)
		assert.Equal(t, codes.Aborted, status.Code(err))
	})

	t.Run("missing fields returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Update(userCtx(), &pb.UpdateSecretRequest{Name: "x", Payload: []byte("y")})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("unauthenticated returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Update(context.Background(), &pb.UpdateSecretRequest{
			Id: "x", Name: "n", Payload: []byte("p"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestSecretHandler_Delete(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		deleted := *serverSecret
		deleted.Deleted = true
		svc.EXPECT().Delete(gomock.Any(), "user-1", "secret-uuid-1", int64(5)).Return(&deleted, nil)

		resp, err := h.Delete(userCtx(), &pb.DeleteSecretRequest{Id: "secret-uuid-1", BaseVersion: 5})
		require.NoError(t, err)
		assert.True(t, resp.GetDeleted())
	})

	t.Run("empty id returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Delete(userCtx(), &pb.DeleteSecretRequest{Id: ""})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("not found returns NotFound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newSecretHandler(ctrl)

		svc.EXPECT().Delete(gomock.Any(), "user-1", "gone", int64(0)).Return(nil, errs.ErrNotFound)

		_, err := h.Delete(userCtx(), &pb.DeleteSecretRequest{Id: "gone"})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("unauthenticated returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newSecretHandler(ctrl)

		_, err := h.Delete(context.Background(), &pb.DeleteSecretRequest{Id: "x"})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}
