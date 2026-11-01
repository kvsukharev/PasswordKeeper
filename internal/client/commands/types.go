package commands

import (
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// pbSecretTypeToModel converts a proto SecretType to model.SecretType.
func pbSecretTypeToModel(t pb.SecretType) model.SecretType {
	switch t {
	case pb.SecretType_SECRET_TYPE_CREDENTIALS:
		return model.SecretTypeCredentials
	case pb.SecretType_SECRET_TYPE_TEXT:
		return model.SecretTypeText
	case pb.SecretType_SECRET_TYPE_BINARY:
		return model.SecretTypeBinary
	case pb.SecretType_SECRET_TYPE_CARD:
		return model.SecretTypeCard
	case pb.SecretType_SECRET_TYPE_OTP:
		return model.SecretTypeOTP
	default:
		return model.SecretType("")
	}
}

// modelSecretTypeToPb converts a model.SecretType to proto SecretType.
func modelSecretTypeToPb(t model.SecretType) pb.SecretType {
	switch t {
	case model.SecretTypeCredentials:
		return pb.SecretType_SECRET_TYPE_CREDENTIALS
	case model.SecretTypeText:
		return pb.SecretType_SECRET_TYPE_TEXT
	case model.SecretTypeBinary:
		return pb.SecretType_SECRET_TYPE_BINARY
	case model.SecretTypeCard:
		return pb.SecretType_SECRET_TYPE_CARD
	case model.SecretTypeOTP:
		return pb.SecretType_SECRET_TYPE_OTP
	default:
		return pb.SecretType_SECRET_TYPE_UNSPECIFIED
	}
}

// pendingActionToPb converts a pending change action string to pb.ChangeAction.
func pendingActionToPb(action string) pb.ChangeAction {
	switch action {
	case "create":
		return pb.ChangeAction_CHANGE_ACTION_CREATE
	case "update":
		return pb.ChangeAction_CHANGE_ACTION_UPDATE
	case "delete":
		return pb.ChangeAction_CHANGE_ACTION_DELETE
	default:
		return pb.ChangeAction_CHANGE_ACTION_UNSPECIFIED
	}
}

// isOfflineError returns true when the error indicates the server is unreachable.
func isOfflineError(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded
}

// localSecretFromPb converts a pb.Secret to a LocalSecret for caching.
func localSecretFromPb(s *pb.Secret) *storage.LocalSecret {
	meta := s.GetMeta()
	var updatedAt time.Time
	if meta.GetUpdatedAt() != nil {
		updatedAt = meta.GetUpdatedAt().AsTime()
	}
	return &storage.LocalSecret{
		ID:        meta.GetId(),
		Type:      pbSecretTypeToModel(meta.GetType()),
		Name:      meta.GetName(),
		Payload:   s.GetPayload(),
		Version:   meta.GetVersion(),
		Deleted:   meta.GetDeleted(),
		UpdatedAt: updatedAt,
	}
}
