package transport_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/errs"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	mockservice "github.com/kvsuharev/passwordkeeper/internal/server/service/mock"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

// ---- Upload stream stub ----

type uploadStream struct {
	ctx    context.Context
	chunks []*pb.UploadChunk
	pos    int
	closed *pb.SecretMeta
}

func newUploadStream(ctx context.Context, chunks []*pb.UploadChunk) *uploadStream {
	return &uploadStream{ctx: ctx, chunks: chunks}
}

func (s *uploadStream) Recv() (*pb.UploadChunk, error) {
	if s.pos >= len(s.chunks) {
		return nil, io.EOF
	}
	c := s.chunks[s.pos]
	s.pos++
	return c, nil
}
func (s *uploadStream) SendAndClose(meta *pb.SecretMeta) error { s.closed = meta; return nil }
func (s *uploadStream) SetHeader(metadata.MD) error            { return nil }
func (s *uploadStream) SendHeader(metadata.MD) error           { return nil }
func (s *uploadStream) SetTrailer(metadata.MD)                 {}
func (s *uploadStream) Context() context.Context               { return s.ctx }
func (s *uploadStream) SendMsg(any) error                      { return nil }
func (s *uploadStream) RecvMsg(any) error                      { return nil }

// ---- Download stream stub ----

type downloadStream struct {
	ctx    context.Context
	chunks []*pb.DownloadChunk
}

func newDownloadStream(ctx context.Context) *downloadStream {
	return &downloadStream{ctx: ctx}
}

func (s *downloadStream) Send(c *pb.DownloadChunk) error { s.chunks = append(s.chunks, c); return nil }
func (s *downloadStream) SetHeader(metadata.MD) error    { return nil }
func (s *downloadStream) SendHeader(metadata.MD) error   { return nil }
func (s *downloadStream) SetTrailer(metadata.MD)         {}
func (s *downloadStream) Context() context.Context       { return s.ctx }
func (s *downloadStream) SendMsg(any) error              { return nil }
func (s *downloadStream) RecvMsg(any) error              { return nil }

// ---- helpers ----

func metaChunk(id, name string) *pb.UploadChunk {
	return &pb.UploadChunk{
		Data: &pb.UploadChunk_Meta{
			Meta: &pb.CreateSecretRequest{
				Id:   id,
				Name: name,
				Type: pb.SecretType_SECRET_TYPE_BINARY,
			},
		},
	}
}

func dataChunk(b []byte) *pb.UploadChunk {
	return &pb.UploadChunk{Data: &pb.UploadChunk_Chunk{Chunk: b}}
}

var binarySecret = &model.Secret{
	ID:        "bin-id",
	UserID:    "user-1",
	Type:      model.SecretTypeBinary,
	Name:      "file.bin",
	Payload:   []byte("binary data"),
	Version:   1,
	UpdatedAt: time.Now(),
}

// ---- Upload tests ----

func TestSecretHandler_Upload_Success(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc := mockservice.NewMockSecretService(ctrl)
	h := transport.NewSecretHandler(svc, 0)

	svc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(binarySecret, nil)

	stream := newUploadStream(userCtx(), []*pb.UploadChunk{
		metaChunk("bin-id", "file.bin"),
		dataChunk([]byte("binary data")),
	})

	err := h.Upload(stream)
	require.NoError(t, err)
	require.NotNil(t, stream.closed)
	assert.Equal(t, "bin-id", stream.closed.GetId())
}

func TestSecretHandler_Upload_Unauthenticated(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	stream := newUploadStream(context.Background(), []*pb.UploadChunk{
		metaChunk("x", "y"),
	})

	err := h.Upload(stream)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestSecretHandler_Upload_FirstFrameNotMeta(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	stream := newUploadStream(userCtx(), []*pb.UploadChunk{
		dataChunk([]byte("oops")), // no meta frame
	})

	err := h.Upload(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSecretHandler_Upload_EmptyIDinMeta(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	stream := newUploadStream(userCtx(), []*pb.UploadChunk{
		metaChunk("", "name"), // empty id
	})

	err := h.Upload(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSecretHandler_Upload_EmptyPayload(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	// Meta frame but no data chunks.
	stream := newUploadStream(userCtx(), []*pb.UploadChunk{
		metaChunk("id", "name"),
	})

	err := h.Upload(stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSecretHandler_Upload_SizeLimitExceeded(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 5) // 5-byte limit

	stream := newUploadStream(userCtx(), []*pb.UploadChunk{
		metaChunk("id", "name"),
		dataChunk([]byte("exceeds")), // 7 bytes > 5
	})

	err := h.Upload(stream)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestSecretHandler_Upload_ServiceError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc := mockservice.NewMockSecretService(ctrl)
	h := transport.NewSecretHandler(svc, 0)

	svc.EXPECT().Create(gomock.Any(), "user-1", gomock.Any()).Return(nil, errs.ErrAlreadyExists)

	stream := newUploadStream(userCtx(), []*pb.UploadChunk{
		metaChunk("id", "name"),
		dataChunk([]byte("payload")),
	})

	err := h.Upload(stream)
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestSecretHandler_Upload_RecvError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	// errStream returns an error on the second Recv (after meta).
	stream := &errUploadStream{ctx: userCtx()}
	err := h.Upload(stream)
	require.Error(t, err)
}

// errUploadStream returns meta on first Recv, then an error.
type errUploadStream struct {
	ctx  context.Context
	recv int
}

func (s *errUploadStream) Recv() (*pb.UploadChunk, error) {
	s.recv++
	if s.recv == 1 {
		return metaChunk("id", "name"), nil
	}
	return nil, errors.New("network failure")
}
func (s *errUploadStream) SendAndClose(*pb.SecretMeta) error { return nil }
func (s *errUploadStream) SetHeader(metadata.MD) error       { return nil }
func (s *errUploadStream) SendHeader(metadata.MD) error      { return nil }
func (s *errUploadStream) SetTrailer(metadata.MD)            {}
func (s *errUploadStream) Context() context.Context          { return s.ctx }
func (s *errUploadStream) SendMsg(any) error                 { return nil }
func (s *errUploadStream) RecvMsg(any) error                 { return nil }

// ---- Download tests ----

func TestSecretHandler_Download_Success(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc := mockservice.NewMockSecretService(ctrl)
	h := transport.NewSecretHandler(svc, 0)

	svc.EXPECT().Get(gomock.Any(), "user-1", "bin-id").Return(binarySecret, nil)

	stream := newDownloadStream(userCtx())
	err := h.Download(&pb.DownloadRequest{Id: "bin-id"}, stream)
	require.NoError(t, err)

	// First frame must be meta; rest are data chunks.
	require.NotEmpty(t, stream.chunks)
	assert.NotNil(t, stream.chunks[0].GetMeta())
	if len(stream.chunks) > 1 {
		assert.NotEmpty(t, stream.chunks[1].GetChunk())
	}
}

func TestSecretHandler_Download_EmptyID(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	stream := newDownloadStream(userCtx())
	err := h.Download(&pb.DownloadRequest{Id: ""}, stream)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSecretHandler_Download_Unauthenticated(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	h := transport.NewSecretHandler(mockservice.NewMockSecretService(ctrl), 0)

	stream := newDownloadStream(context.Background())
	err := h.Download(&pb.DownloadRequest{Id: "bin-id"}, stream)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestSecretHandler_Download_NotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc := mockservice.NewMockSecretService(ctrl)
	h := transport.NewSecretHandler(svc, 0)

	svc.EXPECT().Get(gomock.Any(), "user-1", "missing").Return(nil, errs.ErrNotFound)

	stream := newDownloadStream(userCtx())
	err := h.Download(&pb.DownloadRequest{Id: "missing"}, stream)
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretHandler_Download_LargePayload(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	svc := mockservice.NewMockSecretService(ctrl)
	h := transport.NewSecretHandler(svc, 0)

	// 130 KiB payload — should produce 3 frames (meta + 2 data chunks).
	largePayload := make([]byte, 130*1024)
	large := &model.Secret{
		ID:        "big-id",
		Type:      model.SecretTypeBinary,
		Name:      "big.bin",
		Payload:   largePayload,
		Version:   1,
		UpdatedAt: time.Now(),
	}
	svc.EXPECT().Get(gomock.Any(), "user-1", "big-id").Return(large, nil)

	stream := newDownloadStream(userCtx())
	err := h.Download(&pb.DownloadRequest{Id: "big-id"}, stream)
	require.NoError(t, err)
	// meta + ceil(130*1024/65536) = meta + 3 chunks = 4 total
	assert.Equal(t, 4, len(stream.chunks))
}
