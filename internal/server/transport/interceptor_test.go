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

func newTestManager() *auth.Manager {
	return auth.NewManager("transport-test-secret-long-enough", 15*time.Minute, 30*24*time.Hour)
}

// noopHandler is a gRPC unary handler that does nothing and returns nil.
func noopHandler(_ context.Context, _ any) (any, error) { return nil, nil }

func ctxWithBearer(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestAuthUnaryInterceptor_PublicMethods(t *testing.T) {
	t.Parallel()

	mgr := newTestManager()
	interceptor := transport.AuthUnaryInterceptor(mgr)

	for _, method := range []string{
		"/passwordkeeper.v1.AuthService/Register",
		"/passwordkeeper.v1.AuthService/Login",
	} {
		method := method
		t.Run(method, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{FullMethod: method}
			_, err := interceptor(context.Background(), nil, info, noopHandler)
			require.NoError(t, err)
		})
	}
}

func TestAuthUnaryInterceptor_MissingToken(t *testing.T) {
	t.Parallel()

	mgr := newTestManager()
	interceptor := transport.AuthUnaryInterceptor(mgr)
	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Get"}

	_, err := interceptor(context.Background(), nil, info, noopHandler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthUnaryInterceptor_ValidToken(t *testing.T) {
	t.Parallel()

	mgr := newTestManager()
	interceptor := transport.AuthUnaryInterceptor(mgr)

	token, _, err := mgr.GenerateAccessToken("user-abc")
	require.NoError(t, err)

	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Get"}

	var capturedUserID string
	handler := func(ctx context.Context, _ any) (any, error) {
		id, ok := transport.UserIDFromContext(ctx)
		require.True(t, ok)
		capturedUserID = id
		return nil, nil
	}

	_, err = interceptor(ctxWithBearer(token), nil, info, handler)
	require.NoError(t, err)
	assert.Equal(t, "user-abc", capturedUserID)
}

func TestAuthUnaryInterceptor_InvalidToken(t *testing.T) {
	t.Parallel()

	mgr := newTestManager()
	interceptor := transport.AuthUnaryInterceptor(mgr)
	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Get"}

	_, err := interceptor(ctxWithBearer("invalid.jwt.token"), nil, info, noopHandler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthUnaryInterceptor_MalformedBearer(t *testing.T) {
	t.Parallel()

	mgr := newTestManager()
	interceptor := transport.AuthUnaryInterceptor(mgr)
	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Get"}

	md := metadata.Pairs("authorization", "Token abc")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := interceptor(ctx, nil, info, noopHandler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthUnaryInterceptor_MetadataWithoutAuthorization(t *testing.T) {
	t.Parallel()

	mgr := newTestManager()
	interceptor := transport.AuthUnaryInterceptor(mgr)
	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Get"}

	md := metadata.Pairs("x-custom-header", "value")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := interceptor(ctx, nil, info, noopHandler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
