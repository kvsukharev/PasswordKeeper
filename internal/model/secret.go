package model

import "time"

// SecretType enumerates supported kinds of secrets.
type SecretType string

const (
	// SecretTypeCredentials is a login/password pair with optional URL.
	SecretTypeCredentials SecretType = "credentials"
	// SecretTypeText is arbitrary plaintext.
	SecretTypeText SecretType = "text"
	// SecretTypeBinary is an arbitrary binary file.
	SecretTypeBinary SecretType = "binary"
	// SecretTypeCard is a bank card record.
	SecretTypeCard SecretType = "card"
	// SecretTypeOTP is a TOTP/HOTP one-time-password configuration.
	SecretTypeOTP SecretType = "otp"
)

// Secret is the server-side representation of an encrypted secret.
// The payload field always contains nonce || AES-256-GCM ciphertext; the
// server never sees plaintext.
type Secret struct {
	// ID is the client-generated UUID.
	ID string
	// UserID is the owning user's UUID.
	UserID string
	// Type indicates the kind of data stored in the payload.
	Type SecretType
	// Name is the human-readable label chosen by the user.
	Name string
	// Payload is nonce || AES-256-GCM ciphertext as produced by the client.
	Payload []byte
	// Version is the server-assigned monotonic version number.
	Version int64
	// Deleted is true when the secret has been soft-deleted.
	Deleted bool
	// UpdatedAt is the timestamp of the last server-side modification.
	UpdatedAt time.Time
}

// ChangeAction describes what kind of change a client wants to push.
type ChangeAction string

const (
	// ChangeActionCreate requests creation of a new secret.
	ChangeActionCreate ChangeAction = "create"
	// ChangeActionUpdate requests replacement of an existing secret's payload.
	ChangeActionUpdate ChangeAction = "update"
	// ChangeActionDelete requests soft-deletion of a secret.
	ChangeActionDelete ChangeAction = "delete"
)

// SecretChange is one item in a Push batch.
type SecretChange struct {
	// Action describes the kind of operation.
	Action ChangeAction
	// ID is the target secret UUID.
	ID string
	// Type is required for Create.
	Type SecretType
	// Name is required for Create and Update.
	Name string
	// Payload is the encrypted content; required for Create and Update.
	Payload []byte
	// BaseVersion is the last version seen by the client; 0 for Create.
	BaseVersion int64
}

// ConflictInfo records a push conflict together with the winning server secret.
type ConflictInfo struct {
	// ID is the UUID of the conflicting secret.
	ID string
	// ServerSecret is the current server version that caused the conflict.
	ServerSecret *Secret
}

// ChangeResult is the server's response for one successfully applied change.
type ChangeResult struct {
	// ID is the UUID of the modified secret.
	ID string
	// NewVersion is the version assigned by the server.
	NewVersion int64
}
