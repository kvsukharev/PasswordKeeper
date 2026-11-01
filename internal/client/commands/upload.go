package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// uploadChunkSize is the size of each gRPC streaming frame.
const uploadChunkSize = 64 * 1024 // 64 KiB

func newUploadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Upload and encrypt a binary file",
		Args:  cobra.ExactArgs(1),
		RunE:  runUpload,
	}
	cmd.Flags().String("name", "", "Secret name (defaults to filename)")
	cmd.Flags().StringArray("meta", nil, "Metadata key:value pair (repeatable)")
	cmd.Flags().String("note", "", "Free-text note")
	return cmd
}

func runUpload(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	sessionStore := storage.NewSessionStore(db)
	sess, err := sessionStore.Load(cmd.Context())
	if err != nil {
		return err
	}

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		name = filepath.Base(filePath)
	}

	fileBytes, readErr := os.ReadFile(filePath)
	if readErr != nil {
		return fmt.Errorf("read file: %w", readErr)
	}
	if len(fileBytes) == 0 {
		return fmt.Errorf("file %q is empty", filePath)
	}

	masterPwd, err := ReadPassword("Master password: ")
	if err != nil {
		return err
	}
	encKey := crypto.DeriveEncKey(masterPwd, sess.Login)
	ZeroBytes(masterPwd)
	defer ZeroBytes(encKey)

	id := uuid.New().String()
	aad := crypto.MakeAAD(id, string(model.SecretTypeBinary))

	encrypted, encErr := crypto.Encrypt(encKey, fileBytes, aad)
	if encErr != nil {
		return fmt.Errorf("encrypt file: %w", encErr)
	}

	conn, dialErr := grpcclient.Dial(cfg.ServerAddr, cfg.CACertFile)
	if dialErr != nil {
		return fmt.Errorf("connect to server: %w", dialErr)
	}
	defer conn.Close()

	ctx := cmd.Context()
	if refreshErr := refreshSessionIfNeeded(ctx, conn, sessionStore, sess); refreshErr != nil {
		return refreshErr
	}

	authCtx := grpcclient.AuthCtx(ctx, sess.AccessToken)
	stream, streamErr := conn.Secrets.Upload(authCtx)
	if streamErr != nil {
		return fmt.Errorf("open upload stream: %w", streamErr)
	}

	// First frame: secret metadata.
	if sendErr := stream.Send(&pb.UploadChunk{
		Data: &pb.UploadChunk_Meta{Meta: &pb.CreateSecretRequest{
			Id:   id,
			Type: pb.SecretType_SECRET_TYPE_BINARY,
			Name: name,
		}},
	}); sendErr != nil {
		return fmt.Errorf("send meta frame: %w", sendErr)
	}

	// Subsequent frames: encrypted payload in chunks.
	for offset := 0; offset < len(encrypted); offset += uploadChunkSize {
		end := offset + uploadChunkSize
		if end > len(encrypted) {
			end = len(encrypted)
		}
		if sendErr := stream.Send(&pb.UploadChunk{
			Data: &pb.UploadChunk_Chunk{Chunk: encrypted[offset:end]},
		}); sendErr != nil {
			return fmt.Errorf("send chunk: %w", sendErr)
		}
	}

	meta, recvErr := stream.CloseAndRecv()
	if recvErr != nil {
		return fmt.Errorf("upload: %w", recvErr)
	}

	secrets := storage.NewSecretStore(db)
	if upsertErr := secrets.Upsert(ctx, &storage.LocalSecret{
		ID:        id,
		Type:      model.SecretTypeBinary,
		Name:      name,
		Payload:   encrypted,
		Version:   meta.GetVersion(),
		UpdatedAt: meta.GetUpdatedAt().AsTime(),
	}); upsertErr != nil {
		return fmt.Errorf("cache secret: %w", upsertErr)
	}

	fmt.Printf("Uploaded %q as %q (version %d, %d bytes)\n",
		filePath, name, meta.GetVersion(), len(fileBytes))
	return nil
}
