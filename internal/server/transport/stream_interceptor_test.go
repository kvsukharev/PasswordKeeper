package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

// stubStream is a minimal grpc.ServerStream for testing.
type stubStream struct {
	ctx context.Context
}

func (s *stubStream) SetHeader(metadata.MD) error  { return nil }
func (s *stubStream) SendHeader(metadata.MD) error { return nil }
func (s *stubStream) SetTrailer(metadata.MD)       {}
func (s *stubStream) Context() context.Context     { return s.ctx }
func (s *stubStream) SendMsg(any) error            { return nil }
func (s *stubStream) RecvMsg(any) error            { return nil }

func TestAuthStreamInterceptor_ValidToken(t *testing.T) {
	t.Parallel()

	mgr := auth.NewManager("stream-test-secret-long-enough", 15*time.Minute, 30*24*time.Hour)
	interceptor := transport.AuthStreamInterceptor(mgr)

	token, _, err := mgr.GenerateAccessToken("user-stream")
	require.NoError(t, err)

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &stubStream{ctx: ctx}

	var capturedUserID string
	handler := func(_ any, ss grpc.ServerStream) error {
		id, ok := transport.UserIDFromContext(ss.Context())
		require.True(t, ok)
		capturedUserID = id
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Upload"}
	err = interceptor(nil, stream, info, handler)
	require.NoError(t, err)
	assert.Equal(t, "user-stream", capturedUserID)
}

func TestAuthStreamInterceptor_MissingToken(t *testing.T) {
	t.Parallel()

	mgr := auth.NewManager("stream-test-secret-long-enough", 15*time.Minute, 30*24*time.Hour)
	interceptor := transport.AuthStreamInterceptor(mgr)

	stream := &stubStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Upload"}

	err := interceptor(nil, stream, info, func(_ any, _ grpc.ServerStream) error { return nil })
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthStreamInterceptor_PublicMethod(t *testing.T) {
	t.Parallel()

	mgr := auth.NewManager("stream-test-secret-long-enough", 15*time.Minute, 30*24*time.Hour)
	interceptor := transport.AuthStreamInterceptor(mgr)

	// Refresh is a public method; no token needed.
	stream := &stubStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{FullMethod: "/passwordkeeper.v1.AuthService/Refresh"}

	called := false
	err := interceptor(nil, stream, info, func(_ any, _ grpc.ServerStream) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}
