package transport

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// rateLimitedMethods are the gRPC methods subject to per-IP rate limiting.
var rateLimitedMethods = map[string]struct{}{
	"/passwordkeeper.v1.AuthService/Login":    {},
	"/passwordkeeper.v1.AuthService/Register": {},
}

// ipEntry holds a token-bucket limiter for one remote address.
type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter enforces per-IP token-bucket rate limits.
type RateLimiter struct {
	mu    sync.Mutex
	ips   map[string]*ipEntry
	rps   rate.Limit
	burst int
}

// NewRateLimiter creates a RateLimiter allowing rps sustained requests per
// second with an initial burst of burst. Idle entries are evicted every five
// minutes.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		ips:   make(map[string]*ipEntry),
		rps:   rate.Limit(rps),
		burst: burst,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow reports whether the given address is within its rate limit.
func (rl *RateLimiter) Allow(addr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.ips[addr]
	if !ok {
		e = &ipEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.ips[addr] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// cleanupLoop evicts entries that have not been seen for more than five minutes.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for ip, e := range rl.ips {
			if time.Since(e.lastSeen) > 5*time.Minute {
				delete(rl.ips, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitUnaryInterceptor returns a gRPC unary interceptor that enforces
// per-IP rate limiting on Login and Register. Requests that exceed the limit
// are rejected with codes.ResourceExhausted.
func RateLimitUnaryInterceptor(rl *RateLimiter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, ok := rateLimitedMethods[info.FullMethod]; !ok {
			return handler(ctx, req)
		}

		addr := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			addr = p.Addr.String()
		}

		if !rl.Allow(addr) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", info.FullMethod)
		}
		return handler(ctx, req)
	}
}
