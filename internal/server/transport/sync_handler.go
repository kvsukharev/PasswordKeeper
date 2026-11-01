package transport

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/service"
)

// SyncHandler implements pb.SyncServiceServer.
type SyncHandler struct {
	pb.UnimplementedSyncServiceServer
	svc service.SyncService
}

// NewSyncHandler creates a SyncHandler wired to the given SyncService.
func NewSyncHandler(svc service.SyncService) *SyncHandler {
	return &SyncHandler{svc: svc}
}

// Pull returns all secrets changed after the requested version.
func (h *SyncHandler) Pull(ctx context.Context, req *pb.PullRequest) (*pb.PullResponse, error) {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	secrets, currentVersion, err := h.svc.Pull(ctx, userID, req.GetSinceVersion())
	if err != nil {
		return nil, mapError(err)
	}

	pbSecrets := make([]*pb.Secret, 0, len(secrets))
	for _, s := range secrets {
		pbSecrets = append(pbSecrets, &pb.Secret{
			Meta:    secretToMeta(s),
			Payload: s.Payload,
		})
	}

	return &pb.PullResponse{
		Secrets:        pbSecrets,
		CurrentVersion: currentVersion,
	}, nil
}

// Push applies a batch of local changes to the server.
func (h *SyncHandler) Push(ctx context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	changes := make([]*model.SecretChange, 0, len(req.GetChanges()))
	for _, ch := range req.GetChanges() {
		action, ok := protoActionToModel(ch.GetAction())
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown action %v", ch.GetAction())
		}
		changes = append(changes, &model.SecretChange{
			Action:      action,
			ID:          ch.GetId(),
			Type:        protoTypeToModel(ch.GetType()),
			Name:        ch.GetName(),
			Payload:     ch.GetPayload(),
			BaseVersion: ch.GetBaseVersion(),
		})
	}

	results, conflicts, err := h.svc.Push(ctx, userID, changes)
	if err != nil {
		return nil, mapError(err)
	}

	pbResults := make([]*pb.ChangeResult, 0, len(results))
	for _, r := range results {
		pbResults = append(pbResults, &pb.ChangeResult{Id: r.ID, NewVersion: r.NewVersion})
	}

	pbConflicts := make([]*pb.ConflictInfo, 0, len(conflicts))
	for _, c := range conflicts {
		info := &pb.ConflictInfo{Id: c.ID}
		if c.ServerSecret != nil {
			info.ServerSecret = &pb.Secret{
				Meta:    secretToMeta(c.ServerSecret),
				Payload: c.ServerSecret.Payload,
			}
		}
		pbConflicts = append(pbConflicts, info)
	}

	return &pb.PushResponse{Results: pbResults, Conflicts: pbConflicts}, nil
}

func protoActionToModel(a pb.ChangeAction) (model.ChangeAction, bool) {
	switch a {
	case pb.ChangeAction_CHANGE_ACTION_CREATE:
		return model.ChangeActionCreate, true
	case pb.ChangeAction_CHANGE_ACTION_UPDATE:
		return model.ChangeActionUpdate, true
	case pb.ChangeAction_CHANGE_ACTION_DELETE:
		return model.ChangeActionDelete, true
	default:
		return "", false
	}
}
