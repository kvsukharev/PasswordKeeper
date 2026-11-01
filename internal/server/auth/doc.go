// Package auth implements JWT generation and validation for the PasswordKeeper
// server. It manages access tokens (15-minute JWTs) and refresh tokens
// (30-day opaque tokens stored as hashes in PostgreSQL).
package auth
