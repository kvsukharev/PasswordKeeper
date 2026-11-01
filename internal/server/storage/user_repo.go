package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// pgErrUniqueViolation is the PostgreSQL error code for unique constraint violations.
const pgErrUniqueViolation = "23505"

// userRepo is the PostgreSQL implementation of UserRepository.
type userRepo struct {
	db *pgxpool.Pool
}

// NewUserRepo creates a UserRepository backed by the given pool.
func NewUserRepo(db *pgxpool.Pool) UserRepository {
	return &userRepo{db: db}
}

// Create inserts a new user row. Returns errs.ErrAlreadyExists on duplicate login.
func (r *userRepo) Create(ctx context.Context, user *model.User) error {
	const q = `
		INSERT INTO users (id, login, password_hash, created_at)
		VALUES ($1, $2, $3, $4)`

	_, err := r.db.Exec(ctx, q, user.ID, user.Login, user.PasswordHash, user.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation {
			return fmt.Errorf("create user %q: %w", user.Login, errs.ErrAlreadyExists)
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// GetByLogin fetches a user by login. Returns errs.ErrNotFound if absent.
func (r *userRepo) GetByLogin(ctx context.Context, login string) (*model.User, error) {
	const q = `
		SELECT id, login, password_hash, created_at
		FROM users WHERE login = $1`

	user := &model.User{}
	err := r.db.QueryRow(ctx, q, login).Scan(
		&user.ID, &user.Login, &user.PasswordHash, &user.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by login: %w", err)
	}
	return user, nil
}

// GetByID fetches a user by UUID. Returns errs.ErrNotFound if absent.
func (r *userRepo) GetByID(ctx context.Context, id string) (*model.User, error) {
	const q = `
		SELECT id, login, password_hash, created_at
		FROM users WHERE id = $1`

	user := &model.User{}
	err := r.db.QueryRow(ctx, q, id).Scan(
		&user.ID, &user.Login, &user.PasswordHash, &user.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return user, nil
}
