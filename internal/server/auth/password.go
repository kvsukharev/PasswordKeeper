package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per spec: time=1, memory=64 MiB, threads=4.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MiB in KiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// HashAuthKey derives and encodes an Argon2id hash of the client-supplied auth_key.
// The returned string uses PHC format:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<base64-salt>$<base64-hash>
func HashAuthKey(authKey []byte) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate argon2 salt: %w", err)
	}

	hash := argon2.IDKey(authKey, salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash), nil
}

// VerifyAuthKey checks whether authKey matches the PHC-encoded hash.
func VerifyAuthKey(authKey []byte, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	// expected: ["", "argon2id", "v=19", "m=65536,t=1,p=4", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	actual := argon2.IDKey(authKey, salt, argonTime, argonMemory, argonThreads, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(actual, expectedHash) == 1, nil
}
