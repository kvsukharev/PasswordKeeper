package transport_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

// newRateLimitInterceptor is a test helper that builds the interceptor from rl.
func newRateLimitInterceptor(rl *transport.RateLimiter) grpc.UnaryServerInterceptor {
	return transport.RateLimitUnaryInterceptor(rl)
}

// newZeroRateLimiter creates a limiter with zero budget (every call is denied).
func newZeroRateLimiter() *transport.RateLimiter {
	return transport.NewRateLimiter(0, 0)
}

// newBurst1RateLimiter creates a limiter with 1-token burst and no sustained rate.
func newBurst1RateLimiter() *transport.RateLimiter {
	return transport.NewRateLimiter(0, 1)
}

// newGenerousRateLimiter creates a limiter with high rps/burst for tests that
// should always succeed.
func newGenerousRateLimiter() *transport.RateLimiter {
	return transport.NewRateLimiter(1000, 1000)
}

func TestRateLimitUnaryInterceptor_NonRateLimitedMethod(t *testing.T) {
	t.Parallel()

	// Even a burst=0 limiter must not block non-rate-limited methods.
	rl := newZeroRateLimiter()
	interceptor := newRateLimitInterceptor(rl)
	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.SecretService/Get"}

	_, err := interceptor(context.Background(), nil, info, noopHandler)
	require.NoError(t, err)
}

func TestRateLimitUnaryInterceptor_WithinLimit(t *testing.T) {
	t.Parallel()

	rl := newGenerousRateLimiter()
	interceptor := newRateLimitInterceptor(rl)

	for _, method := range []string{
		"/passwordkeeper.v1.AuthService/Login",
		"/passwordkeeper.v1.AuthService/Register",
	} {
		info := &grpc.UnaryServerInfo{FullMethod: method}
		_, err := interceptor(context.Background(), nil, info, noopHandler)
		require.NoError(t, err, "method %s should be allowed", method)
	}
}

func TestRateLimitUnaryInterceptor_ExceedsLimit(t *testing.T) {
	t.Parallel()

	// burst=1, rps=0 → first call consumed by burst, second rejected.
	rl := newZeroRateLimiter()
	// Allow the first call by giving burst=1.
	rlOne := newBurst1RateLimiter()
	interceptor := newRateLimitInterceptor(rlOne)
	info := &grpc.UnaryServerInfo{FullMethod: "/passwordkeeper.v1.AuthService/Login"}

	_, err := interceptor(context.Background(), nil, info, noopHandler)
	require.NoError(t, err, "first call within burst should succeed")

	// Reuse the zero-limiter which has no budget at all.
	interceptor2 := newRateLimitInterceptor(rl)
	_, err = interceptor2(context.Background(), nil, info, noopHandler)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestRateLimitUnaryInterceptor_DirectAllow(t *testing.T) {
	t.Parallel()

	rl := newGenerousRateLimiter()
	assert.True(t, rl.Allow("192.0.2.1:1234"))
	assert.True(t, rl.Allow("192.0.2.1:1234"))
}
