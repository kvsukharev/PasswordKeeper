package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"
)

// Session holds the authenticated user's runtime state persisted locally.
type Session struct {
	// Login is the username of the authenticated user.
	Login string
	// AccessToken is the current JWT access token.
	AccessToken string
	// RefreshToken is the current raw refresh token.
	RefreshToken string
	// ExpiresAt is the expiry time of the access token.
	ExpiresAt time.Time
}

// SessionStore persists and retrieves session data in the local SQLite database.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore creates a SessionStore backed by db.
func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Save writes all session fields to the session table (upsert).
func (s *SessionStore) Save(ctx context.Context, sess *Session) error {
	pairs := map[string]string{
		"login":         sess.Login,
		"access_token":  sess.AccessToken,
		"refresh_token": sess.RefreshToken,
		"expires_at":    sess.ExpiresAt.UTC().Format(time.RFC3339),
	}
	for k, v := range pairs {
		if err := s.set(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

// Load reads all session fields from the session table.
// Returns ErrNoSession if no session is stored.
func (s *SessionStore) Load(ctx context.Context) (*Session, error) {
	keys := []string{"login", "access_token", "refresh_token", "expires_at"}
	vals := make(map[string]string, len(keys))

	for _, k := range keys {
		v, err := s.get(ctx, k)
		if err != nil {
			return nil, ErrNoSession
		}
		vals[k] = v
	}

	expiresAt, err := time.Parse(time.RFC3339, vals["expires_at"])
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}

	return &Session{
		Login:        vals["login"],
		AccessToken:  vals["access_token"],
		RefreshToken: vals["refresh_token"],
		ExpiresAt:    expiresAt,
	}, nil
}

// Clear removes all session data from the table.
func (s *SessionStore) Clear(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session`)
	if err != nil {
		return fmt.Errorf("clear session: %w", err)
	}
	return nil
}

// UpdateTokens replaces only the token fields in the session.
func (s *SessionStore) UpdateTokens(ctx context.Context, accessToken, refreshToken string, expiresAt time.Time) error {
	pairs := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_at":    expiresAt.UTC().Format(time.RFC3339),
	}
	for k, v := range pairs {
		if err := s.set(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

func (s *SessionStore) set(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO session(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	if err != nil {
		return fmt.Errorf("set session[%s]: %w", key, err)
	}
	return nil
}

func (s *SessionStore) get(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM session WHERE key=?`, key).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("get session[%s]: %w", key, err)
	}
	return value, nil
}

// GetSyncVersion returns the last successfully synced server version (0 if not set).
func (s *SessionStore) GetSyncVersion(ctx context.Context) (int64, error) {
	v, err := s.get(ctx, "sync_version")
	if err != nil {
		return 0, nil
	}
	n, parseErr := strconv.ParseInt(v, 10, 64)
	if parseErr != nil {
		return 0, fmt.Errorf("parse sync_version: %w", parseErr)
	}
	return n, nil
}

// SetSyncVersion persists the last successfully synced server version.
func (s *SessionStore) SetSyncVersion(ctx context.Context, version int64) error {
	return s.set(ctx, "sync_version", strconv.FormatInt(version, 10))
}

// ErrNoSession is returned when no active session is found in the local database.
var ErrNoSession = fmt.Errorf("not logged in: run 'passwordkeeper login' first")
