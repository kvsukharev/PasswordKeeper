package transport

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/service"
)

// streamChunkSize is the size of each payload frame sent during Download.
const streamChunkSize = 64 * 1024 // 64 KiB

// SecretHandler implements pb.SecretServiceServer.
type SecretHandler struct {
	pb.UnimplementedSecretServiceServer
	svc            service.SecretService
	maxBinaryBytes int64
}

// NewSecretHandler creates a SecretHandler wired to the given SecretService.
// maxBinaryBytes limits the total payload accepted by Upload (0 = no limit).
func NewSecretHandler(svc service.SecretService, maxBinaryBytes int64) *SecretHandler {
	return &SecretHandler{svc: svc, maxBinaryBytes: maxBinaryBytes}
}

// Create stores a new encrypted secret.
func (h *SecretHandler) Create(ctx context.Context, req *pb.CreateSecretRequest) (*pb.SecretMeta, error) {
	if req.GetId() == "" || req.GetName() == "" || len(req.GetPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "id, name and payload are required")
	}

	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	s := &model.Secret{
		ID:      req.GetId(),
		Type:    protoTypeToModel(req.GetType()),
		Name:    req.GetName(),
		Payload: req.GetPayload(),
	}

	created, err := h.svc.Create(ctx, userID, s)
	if err != nil {
		return nil, mapError(err)
	}

	return secretToMeta(created), nil
}

// Get returns a single secret including its encrypted payload.
func (h *SecretHandler) Get(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	s, err := h.svc.Get(ctx, userID, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}

	return &pb.Secret{
		Meta:    secretToMeta(s),
		Payload: s.Payload,
	}, nil
}

// Update replaces the payload of an existing secret using optimistic concurrency.
func (h *SecretHandler) Update(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.SecretMeta, error) {
	if req.GetId() == "" || req.GetName() == "" || len(req.GetPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "id, name and payload are required")
	}

	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	s := &model.Secret{
		ID:      req.GetId(),
		Name:    req.GetName(),
		Payload: req.GetPayload(),
	}

	updated, err := h.svc.Update(ctx, userID, s, req.GetBaseVersion())
	if err != nil {
		return nil, mapError(err)
	}

	return secretToMeta(updated), nil
}

// Delete soft-deletes a secret using optimistic concurrency.
func (h *SecretHandler) Delete(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.SecretMeta, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	deleted, err := h.svc.Delete(ctx, userID, req.GetId(), req.GetBaseVersion())
	if err != nil {
		return nil, mapError(err)
	}

	return secretToMeta(deleted), nil
}

// Upload receives a client-streaming binary upload and stores the assembled payload.
// Protocol: first frame must be UploadChunk_Meta; subsequent frames are UploadChunk_Chunk.
func (h *SecretHandler) Upload(stream grpc.ClientStreamingServer[pb.UploadChunk, pb.SecretMeta]) error {
	ctx := stream.Context()
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}

	// First frame must carry the secret metadata.
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "expected meta frame: %v", err)
	}
	req := first.GetMeta()
	if req == nil {
		return status.Error(codes.InvalidArgument, "first frame must be meta")
	}
	if req.GetId() == "" || req.GetName() == "" {
		return status.Error(codes.InvalidArgument, "id and name are required in meta")
	}

	// Accumulate payload chunks.
	var buf []byte
	var total int64
	for {
		msg, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return status.Errorf(codes.Internal, "receive chunk: %v", recvErr)
		}
		chunk := msg.GetChunk()
		if len(chunk) == 0 {
			continue
		}
		total += int64(len(chunk))
		if h.maxBinaryBytes > 0 && total > h.maxBinaryBytes {
			return status.Errorf(codes.ResourceExhausted,
				"payload exceeds maximum of %d bytes", h.maxBinaryBytes)
		}
		buf = append(buf, chunk...)
	}
	if len(buf) == 0 {
		return status.Error(codes.InvalidArgument, "payload is empty")
	}

	s := &model.Secret{
		ID:      req.GetId(),
		Type:    protoTypeToModel(req.GetType()),
		Name:    req.GetName(),
		Payload: buf,
	}

	created, createErr := h.svc.Create(ctx, userID, s)
	if createErr != nil {
		return mapError(createErr)
	}

	return stream.SendAndClose(secretToMeta(created))
}

// Download streams a secret's encrypted payload to the client in 64-KiB chunks.
// Protocol: first frame is DownloadChunk_Meta; subsequent frames are DownloadChunk_Chunk.
func (h *SecretHandler) Download(req *pb.DownloadRequest, stream grpc.ServerStreamingServer[pb.DownloadChunk]) error {
	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, "id is required")
	}

	ctx := stream.Context()
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}

	s, err := h.svc.Get(ctx, userID, req.GetId())
	if err != nil {
		return mapError(err)
	}

	// First frame: secret metadata.
	if sendErr := stream.Send(&pb.DownloadChunk{
		Data: &pb.DownloadChunk_Meta{Meta: secretToMeta(s)},
	}); sendErr != nil {
		return sendErr
	}

	// Subsequent frames: encrypted payload split into chunks.
	for offset := 0; offset < len(s.Payload); offset += streamChunkSize {
		end := offset + streamChunkSize
		if end > len(s.Payload) {
			end = len(s.Payload)
		}
		if sendErr := stream.Send(&pb.DownloadChunk{
			Data: &pb.DownloadChunk_Chunk{Chunk: s.Payload[offset:end]},
		}); sendErr != nil {
			return sendErr
		}
	}
	return nil
}

func secretToMeta(s *model.Secret) *pb.SecretMeta {
	return &pb.SecretMeta{
		Id:        s.ID,
		Type:      modelTypeToProto(s.Type),
		Name:      s.Name,
		Version:   s.Version,
		Deleted:   s.Deleted,
		UpdatedAt: timestamppb.New(s.UpdatedAt),
	}
}

// ProtoTypeToModel is exported for use in tests.
var ProtoTypeToModel = protoTypeToModel

// ModelTypeToProto is exported for use in tests.
var ModelTypeToProto = modelTypeToProto

func protoTypeToModel(t pb.SecretType) model.SecretType {
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

func modelTypeToProto(t model.SecretType) pb.SecretType {
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
