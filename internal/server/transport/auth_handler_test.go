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

func newAuthHandler(ctrl *gomock.Controller) (*transport.AuthHandler, *mockservice.MockAuthService) {
	svc := mockservice.NewMockAuthService(ctrl)
	return transport.NewAuthHandler(svc), svc
}

func TestRegisterHandler(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Register(gomock.Any(), "alice", []byte("key")).Return(&model.TokenPair{
			AccessToken:  "access",
			RefreshToken: "refresh",
			ExpiresAt:    time.Now().Add(15 * time.Minute),
		}, nil)

		resp, err := h.Register(context.Background(), &pb.RegisterRequest{
			Login: "alice", AuthKey: []byte("key"),
		})
		require.NoError(t, err)
		assert.Equal(t, "access", resp.AccessToken)
	})

	t.Run("missing fields returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newAuthHandler(ctrl)

		_, err := h.Register(context.Background(), &pb.RegisterRequest{Login: ""})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("duplicate login returns AlreadyExists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Register(gomock.Any(), "alice", gomock.Any()).Return(nil, errs.ErrAlreadyExists)

		_, err := h.Register(context.Background(), &pb.RegisterRequest{
			Login: "alice", AuthKey: []byte("key"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.AlreadyExists, status.Code(err))
	})
}

func TestLoginHandler(t *testing.T) {
	t.Parallel()

	t.Run("missing fields returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newAuthHandler(ctrl)

		_, err := h.Login(context.Background(), &pb.LoginRequest{Login: ""})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Login(gomock.Any(), "alice", []byte("key")).Return(&model.TokenPair{
			AccessToken: "tok", RefreshToken: "ref", ExpiresAt: time.Now().Add(time.Minute),
		}, nil)

		resp, err := h.Login(context.Background(), &pb.LoginRequest{
			Login: "alice", AuthKey: []byte("key"),
		})
		require.NoError(t, err)
		assert.Equal(t, "tok", resp.AccessToken)
	})

	t.Run("bad credentials returns Unauthenticated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Login(gomock.Any(), "alice", gomock.Any()).Return(nil, errs.ErrUnauthenticated)

		_, err := h.Login(context.Background(), &pb.LoginRequest{
			Login: "alice", AuthKey: []byte("bad"),
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestRefreshHandler(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Refresh(gomock.Any(), "rawtoken").Return(&model.TokenPair{
			AccessToken: "new", RefreshToken: "new-ref", ExpiresAt: time.Now().Add(time.Minute),
		}, nil)

		resp, err := h.Refresh(context.Background(), &pb.RefreshRequest{RefreshToken: "rawtoken"})
		require.NoError(t, err)
		assert.Equal(t, "new", resp.AccessToken)
	})

	t.Run("empty token returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newAuthHandler(ctrl)

		_, err := h.Refresh(context.Background(), &pb.RefreshRequest{RefreshToken: ""})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("service error is mapped", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Refresh(gomock.Any(), "tok").Return(nil, errs.ErrUnauthenticated)

		_, err := h.Refresh(context.Background(), &pb.RefreshRequest{RefreshToken: "tok"})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestLogoutHandler(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Logout(gomock.Any(), "tok").Return(nil)

		_, err := h.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: "tok"})
		require.NoError(t, err)
	})

	t.Run("empty token returns InvalidArgument", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, _ := newAuthHandler(ctrl)

		_, err := h.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: ""})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("service error is mapped", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		h, svc := newAuthHandler(ctrl)

		svc.EXPECT().Logout(gomock.Any(), "tok").Return(errs.ErrUnauthenticated)

		_, err := h.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: "tok"})
		require.Error(t, err)
	})
}
