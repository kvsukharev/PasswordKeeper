package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// OpenDB opens (or creates) the local SQLite cache database at
// {dataDir}/cache.db with restricted file permissions.
func OpenDB(dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "cache.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Restrict file permissions.
	if err := os.Chmod(dbPath, 0o600); err != nil && !os.IsNotExist(err) {
		db.Close()
		return nil, fmt.Errorf("chmod db file: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite is single-writer

	if err := applySchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return db, nil
}

// applySchema creates all tables if they do not exist.
func applySchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS session (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS secrets (
			id          TEXT PRIMARY KEY,
			type        TEXT NOT NULL,
			name        TEXT NOT NULL,
			payload     BLOB NOT NULL,
			version     INTEGER NOT NULL DEFAULT 0,
			deleted     INTEGER NOT NULL DEFAULT 0,
			updated_at  TEXT NOT NULL,
			is_conflict INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS pending_changes (
			id           TEXT NOT NULL,
			action       TEXT NOT NULL,
			type         TEXT NOT NULL,
			name         TEXT NOT NULL,
			payload      BLOB,
			base_version INTEGER NOT NULL DEFAULT 0,
			queued_at    TEXT NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("create tables: %w", err)
	}
	return nil
}
