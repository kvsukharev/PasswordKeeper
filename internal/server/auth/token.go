package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claims is the JWT payload for access tokens.
type claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

// Manager creates and validates JWTs and refresh tokens.
type Manager struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewManager returns a Manager with the given signing secret and token lifetimes.
func NewManager(secret string, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		secret:     []byte(secret),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// RefreshTTL returns the configured refresh token lifetime.
func (m *Manager) RefreshTTL() time.Duration {
	return m.refreshTTL
}

// GenerateAccessToken creates a signed HS256 JWT for the given user.
// Returns the token string and its expiry time.
func (m *Manager) GenerateAccessToken(userID string) (string, time.Time, error) {
	expiresAt := time.Now().Add(m.accessTTL)
	c := &claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expiresAt, nil
}

// ValidateAccessToken parses and validates a signed JWT and returns the userID.
func (m *Manager) ValidateAccessToken(tokenStr string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("parse access token: %w", err)
	}

	c, ok := token.Claims.(*claims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token claims")
	}
	return c.UserID, nil
}

// GenerateRefreshToken creates a cryptographically random refresh token.
// Returns the raw base64url-encoded token (sent to the client) and its SHA-256
// hex hash (stored in the database).
func GenerateRefreshToken() (raw, hash string, err error) {
	rawBytes := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, rawBytes); err != nil {
		return "", "", fmt.Errorf("generate refresh token bytes: %w", err)
	}
	raw = base64.URLEncoding.EncodeToString(rawBytes)
	hash = hashToken(rawBytes)
	return raw, hash, nil
}

// HashRefreshToken derives the storage hash for a raw base64url-encoded token.
func HashRefreshToken(raw string) (string, error) {
	rawBytes, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("decode refresh token: %w", err)
	}
	return hashToken(rawBytes), nil
}

// hashToken returns the hex-encoded SHA-256 hash of raw token bytes.
func hashToken(rawBytes []byte) string {
	sum := sha256.Sum256(rawBytes)
	return hex.EncodeToString(sum[:])
}
