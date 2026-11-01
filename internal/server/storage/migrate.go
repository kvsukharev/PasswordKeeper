package storage

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // register "pgx" driver for database/sql
	"github.com/pressly/goose/v3"

	"github.com/kvsuharev/passwordkeeper/migrations"
)

// RunMigrations applies all pending goose migrations from the embedded SQL files.
// It opens a separate database/sql connection for goose (pgxpool cannot be used
// directly with goose) and closes it after migrations complete.
func RunMigrations(_ context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open db for migrations: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, "."); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}
