package errs

import "fmt"

// ConflictError is returned when an update or delete fails because the client's
// base_version does not match the current server version. It wraps ErrAborted
// so errors.Is(err, ErrAborted) returns true.
type ConflictError struct {
	CurrentVersion int64
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s: current version is %d", ErrAborted, e.CurrentVersion)
}

// Is makes ConflictError satisfy errors.Is checks against ErrAborted.
func (e *ConflictError) Is(target error) bool {
	return target == ErrAborted
}
