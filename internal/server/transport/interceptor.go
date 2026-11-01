package transport

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
)

// publicMethods lists gRPC full method names that do not require a Bearer access
// token. Register and Login use password-based auth; Refresh authenticates via
// the refresh token carried in the request body.
var publicMethods = map[string]struct{}{
	"/passwordkeeper.v1.AuthService/Register": {},
	"/passwordkeeper.v1.AuthService/Login":    {},
	"/passwordkeeper.v1.AuthService/Refresh":  {},
}

// AuthUnaryInterceptor returns a gRPC unary interceptor that validates the
// access JWT on all non-public methods and injects the userID into the context.
func AuthUnaryInterceptor(mgr *auth.Manager) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, ok := publicMethods[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		userID, err := extractUserID(ctx, mgr)
		if err != nil {
			return nil, err
		}

		return handler(ContextWithUserID(ctx, userID), req)
	}
}

// AuthStreamInterceptor returns a gRPC stream interceptor that validates the
// access JWT on all non-public streaming methods.
func AuthStreamInterceptor(mgr *auth.Manager) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if _, ok := publicMethods[info.FullMethod]; ok {
			return handler(srv, ss)
		}

		userID, err := extractUserID(ss.Context(), mgr)
		if err != nil {
			return err
		}

		return handler(srv, &wrappedStream{ss, ContextWithUserID(ss.Context(), userID)})
	}
}

// extractUserID parses the Bearer token from incoming metadata and returns the
// embedded userID.
func extractUserID(ctx context.Context, mgr *auth.Manager) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	bearer := values[0]
	if !strings.HasPrefix(bearer, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "authorization header must start with 'Bearer '")
	}

	tokenStr := strings.TrimPrefix(bearer, "Bearer ")
	userID, err := mgr.ValidateAccessToken(tokenStr)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	return userID, nil
}

// wrappedStream overrides the context of a ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the overridden context.
func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
