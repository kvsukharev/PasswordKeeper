package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

func newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a secret from the server and local cache",
		Args:  cobra.ExactArgs(1),
		RunE:  runDelete,
	}
	cmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	return cmd
}

func runDelete(cmd *cobra.Command, args []string) error {
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

	secrets := storage.NewSecretStore(db)
	sec, err := secrets.GetByName(cmd.Context(), args[0])
	if err != nil {
		return fmt.Errorf("secret %q not found in local cache", args[0])
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		answer, readErr := ReadLine(fmt.Sprintf("Delete secret %q? [y/N]: ", sec.Name))
		if readErr != nil {
			return readErr
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
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
	_, err = conn.Secrets.Delete(authCtx, &pb.DeleteSecretRequest{
		Id:          sec.ID,
		BaseVersion: sec.Version,
	})
	if err != nil {
		if isOfflineError(err) {
			pending := storage.NewPendingStore(db)
			_ = pending.Enqueue(ctx, &storage.PendingChange{
				ID:          sec.ID,
				Action:      "delete",
				Type:        sec.Type,
				Name:        sec.Name,
				BaseVersion: sec.Version,
			})
			_ = secrets.SoftDelete(ctx, sec.ID)
			fmt.Printf("Offline: deletion of %q queued for next sync.\n", sec.Name)
			return nil
		}
		return fmt.Errorf("delete secret: %w", err)
	}

	if softDelErr := secrets.SoftDelete(ctx, sec.ID); softDelErr != nil {
		return fmt.Errorf("update local cache: %w", softDelErr)
	}

	fmt.Printf("Secret %q deleted.\n", sec.Name)
	return nil
}
