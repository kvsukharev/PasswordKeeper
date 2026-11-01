package transport

import "context"

// ctxKey is an unexported type for context keys in this package.
type ctxKey string

const ctxUserID ctxKey = "userID"

// ContextWithUserID returns a new context with the authenticated user's ID stored.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxUserID, userID)
}

// UserIDFromContext extracts the authenticated user's ID from ctx.
// Returns the empty string and false if the ID is absent.
func UserIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxUserID).(string)
	return v, ok
}
