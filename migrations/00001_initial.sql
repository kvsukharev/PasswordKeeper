-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- version_seq provides monotonically increasing version numbers shared across
-- all secrets of all users so that a single since_version value is sufficient
-- for a client to pull everything it missed.
CREATE SEQUENCE version_seq START 1;

CREATE TABLE secrets (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    name       TEXT NOT NULL,
    payload    BYTEA NOT NULL,
    version    BIGINT NOT NULL DEFAULT nextval('version_seq'),
    deleted    BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX secrets_user_version ON secrets(user_id, version);

CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX refresh_tokens_user_id ON refresh_tokens(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS secrets;
DROP SEQUENCE IF EXISTS version_seq;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
