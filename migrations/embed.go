// Package migrations embeds the goose SQL migration files so the server binary
// can run schema upgrades without access to the source tree at runtime.
package migrations

import "embed"

// FS contains all *.sql migration files in this directory.
//
//go:embed *.sql
var FS embed.FS
