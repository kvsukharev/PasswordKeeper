// Package errs defines sentinel errors shared across all layers of the
// PasswordKeeper server. Using a dedicated package avoids import cycles between
// the storage, service, and transport layers.
package errs
