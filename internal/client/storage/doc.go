// Package storage manages the client-side SQLite cache of encrypted secrets.
// It uses modernc.org/sqlite (pure Go, no CGO) so the client binary can be
// cross-compiled without a C toolchain.
package storage
