// Package sync implements the version-based synchronisation protocol between
// the PasswordKeeper client and server. It manages the local change queue, calls
// Pull and Push, and handles conflict resolution.
package sync
