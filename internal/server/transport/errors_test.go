package transport_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

func TestMapError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		code codes.Code
	}{
		{"not found", errs.ErrNotFound, codes.NotFound},
		{"already exists", errs.ErrAlreadyExists, codes.AlreadyExists},
		{"unauthenticated", errs.ErrUnauthenticated, codes.Unauthenticated},
		{"invalid argument", errs.ErrInvalidArgument, codes.InvalidArgument},
		{"aborted (ConflictError)", &errs.ConflictError{CurrentVersion: 5}, codes.Aborted},
		{"unknown error", assert.AnError, codes.Internal},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mapped := transport.MapError(c.err)
			assert.Equal(t, c.code, status.Code(mapped))
		})
	}
}
