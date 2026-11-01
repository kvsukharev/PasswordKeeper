package model

import "time"

// User represents a registered account on the server.
type User struct {
	// ID is the UUID primary key.
	ID string
	// Login is the unique username (3–64 characters).
	Login string
	// PasswordHash is the Argon2id hash of the auth_key received from the client.
	PasswordHash string
	// CreatedAt is the account creation timestamp.
	CreatedAt time.Time
}

// RefreshToken represents an issued refresh token stored on the server.
type RefreshToken struct {
	// TokenHash is the SHA-256 hash of the raw token bytes.
	TokenHash string
	// UserID is the owner of this token.
	UserID string
	// ExpiresAt is the expiry timestamp.
	ExpiresAt time.Time
}
