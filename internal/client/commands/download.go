package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

func newDownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download <name> [<output-path>]",
		Short: "Download and decrypt a binary file",
		Args:  cobra.RangeArgs(1, 2),
		RunE:  runDownload,
	}
	return cmd
}

func runDownload(cmd *cobra.Command, args []string) error {
	secretName := args[0]
	outPath := secretName // default: save to current directory with secret name
	if len(args) == 2 {
		outPath = args[1]
	}

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

	// Look up secret ID from local cache.
	secrets := storage.NewSecretStore(db)
	sec, err := secrets.GetByName(cmd.Context(), secretName)
	if err != nil {
		return fmt.Errorf("secret %q not found in local cache (run 'list' first)", secretName)
	}

	masterPwd, err := ReadPassword("Master password: ")
	if err != nil {
		return err
	}
	encKey := crypto.DeriveEncKey(masterPwd, sess.Login)
	ZeroBytes(masterPwd)
	defer ZeroBytes(encKey)

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
	stream, streamErr := conn.Secrets.Download(authCtx, &pb.DownloadRequest{Id: sec.ID})
	if streamErr != nil {
		return fmt.Errorf("open download stream: %w", streamErr)
	}

	// First frame must be metadata.
	first, recvErr := stream.Recv()
	if recvErr != nil {
		return fmt.Errorf("receive meta frame: %w", recvErr)
	}
	if first.GetMeta() == nil {
		return fmt.Errorf("expected meta frame as first message")
	}

	// Accumulate encrypted payload from subsequent chunk frames.
	var encPayload []byte
	for {
		msg, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return fmt.Errorf("receive chunk: %w", recvErr)
		}
		encPayload = append(encPayload, msg.GetChunk()...)
	}

	// Decrypt.
	aad := crypto.MakeAAD(sec.ID, string(sec.Type))
	plaintext, decErr := crypto.Decrypt(encKey, encPayload, aad)
	if decErr != nil {
		return fmt.Errorf("decrypt failed (wrong master password?): %w", decErr)
	}

	// Write to output file.
	if writeErr := os.WriteFile(outPath, plaintext, 0o600); writeErr != nil {
		return fmt.Errorf("write output file: %w", writeErr)
	}

	// Update local cache with fresh encrypted payload.
	meta := first.GetMeta()
	if upsertErr := secrets.Upsert(ctx, &storage.LocalSecret{
		ID:        sec.ID,
		Type:      sec.Type,
		Name:      sec.Name,
		Payload:   encPayload,
		Version:   meta.GetVersion(),
		UpdatedAt: meta.GetUpdatedAt().AsTime(),
	}); upsertErr != nil {
		return fmt.Errorf("update local cache: %w", upsertErr)
	}

	fmt.Printf("Downloaded %q to %q (%d bytes)\n", secretName, outPath, len(plaintext))
	return nil
}
