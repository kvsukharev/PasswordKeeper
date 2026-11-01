package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

// newLogoutCmd creates the `logout` subcommand.
func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Invalidate the current session on the server and clear local tokens",
		RunE:  runLogout,
	}
}

func runLogout(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	store := storage.NewSessionStore(db)
	sess, err := store.Load(cmd.Context())
	if err != nil {
		return err
	}

	conn, err := grpcclient.Dial(cfg.ServerAddr, cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer conn.Close()

	ctx := cmd.Context()

	// Auto-refresh the access token if it is about to expire.
	if time.Now().After(sess.ExpiresAt.Add(-30 * time.Second)) {
		refreshResp, refreshErr := conn.Auth.Refresh(ctx, &pb.RefreshRequest{
			RefreshToken: sess.RefreshToken,
		})
		if refreshErr != nil {
			// If refresh fails, clear the local session anyway.
			_ = store.Clear(ctx)
			fmt.Println("Logged out (session already expired on server)")
			return nil
		}
		sess.AccessToken = refreshResp.AccessToken
		sess.RefreshToken = refreshResp.RefreshToken
		sess.ExpiresAt = refreshResp.ExpiresAt.AsTime()
		if updateErr := store.UpdateTokens(ctx, sess.AccessToken, sess.RefreshToken, sess.ExpiresAt); updateErr != nil {
			return updateErr
		}
	}

	authCtx := grpcclient.AuthCtx(ctx, sess.AccessToken)
	_, err = conn.Auth.Logout(authCtx, &pb.LogoutRequest{
		RefreshToken: sess.RefreshToken,
	})
	if err != nil {
		// Clear local session even if the server call fails.
		_ = store.Clear(ctx)
		return fmt.Errorf("server logout failed: %w", err)
	}

	if err := store.Clear(ctx); err != nil {
		return fmt.Errorf("clear local session: %w", err)
	}

	fmt.Println("Logged out")
	return nil
}
