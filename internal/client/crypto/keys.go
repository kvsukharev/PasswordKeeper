package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

// Key derivation parameters (must match server-side registration parameters).
const (
	kdfTime    uint32 = 1
	kdfMemory  uint32 = 64 * 1024 // 64 MiB
	kdfThreads uint8  = 4
	kdfKeyLen  uint32 = 32
)

// DeriveAuthKey derives the auth_key from the master password and login.
// The result is sent to the server during Register and Login; it never contains
// any information that can reconstruct the encryption key.
//
// Salt = SHA-256("passwordkeeper:auth:" + login).
func DeriveAuthKey(password []byte, login string) []byte {
	salt := deriveSalt("passwordkeeper:auth:", login)
	return argon2.IDKey(password, salt, kdfTime, kdfMemory, kdfThreads, kdfKeyLen)
}

// DeriveEncKey derives the local encryption key from the master password and
// login. This key never leaves the client and is never persisted to disk.
//
// Salt = SHA-256("passwordkeeper:enc:" + login).
func DeriveEncKey(password []byte, login string) []byte {
	salt := deriveSalt("passwordkeeper:enc:", login)
	return argon2.IDKey(password, salt, kdfTime, kdfMemory, kdfThreads, kdfKeyLen)
}

// deriveSalt returns SHA-256(prefix + login) as a deterministic 32-byte salt.
func deriveSalt(prefix, login string) []byte {
	h := sha256.Sum256([]byte(prefix + login))
	return h[:]
}
