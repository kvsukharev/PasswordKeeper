// Package crypto implements the client-side zero-knowledge cryptography for
// PasswordKeeper. It derives auth_key and the encryption key from the master
// password using Argon2id and encrypts/decrypts secrets with AES-256-GCM.
package crypto
