package model

import "time"

// TokenPair holds the access JWT and the raw refresh token returned to a client
// after successful authentication.
type TokenPair struct {
	// AccessToken is a signed HS256 JWT valid for 15 minutes.
	AccessToken string
	// RefreshToken is an opaque random token valid for 30 days.
	RefreshToken string
	// ExpiresAt is the expiry time of the access token.
	ExpiresAt time.Time
}
