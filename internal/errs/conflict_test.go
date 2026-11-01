package errs_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
)

func TestConflictError_Error(t *testing.T) {
	e := &errs.ConflictError{CurrentVersion: 42}
	assert.Contains(t, e.Error(), "42")
	assert.Contains(t, e.Error(), "aborted")
}

func TestConflictError_Is(t *testing.T) {
	e := &errs.ConflictError{CurrentVersion: 7}
	assert.True(t, errors.Is(e, errs.ErrAborted))
	assert.False(t, errors.Is(e, errs.ErrNotFound))
}

func TestConflictError_Unwrap(t *testing.T) {
	e := &errs.ConflictError{CurrentVersion: 1}
	wrapped := fmt.Errorf("outer: %w", e)
	assert.True(t, errors.Is(wrapped, errs.ErrAborted))
}
