package transport

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kvsuharev/passwordkeeper/internal/errs"
)

// MapError converts a domain error into the appropriate gRPC status error.
// Unknown errors are returned as Internal to avoid leaking implementation details.
func MapError(err error) error {
	return mapError(err)
}

func mapError(err error) error {
	switch {
	case errors.Is(err, errs.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, errs.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, "already exists")
	case errors.Is(err, errs.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, "unauthenticated")
	case errors.Is(err, errs.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, errs.ErrAborted):
		return status.Error(codes.Aborted, "version conflict")
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}
