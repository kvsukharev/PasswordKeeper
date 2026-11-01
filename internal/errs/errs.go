package errs

import "errors"

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")

// ErrAlreadyExists is returned when a resource with the same unique key already exists.
var ErrAlreadyExists = errors.New("already exists")

// ErrUnauthenticated is returned when authentication fails or credentials are invalid.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrInvalidArgument is returned when an input value fails validation.
var ErrInvalidArgument = errors.New("invalid argument")

// ErrAborted is returned when an operation fails due to a version conflict.
var ErrAborted = errors.New("aborted: version conflict")
