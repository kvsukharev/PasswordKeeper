package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

// newLoginCmd creates the `login` subcommand.
func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the server and sync secrets",
		RunE:  runLogin,
	}
}

func runLogin(cmd *cobra.Command, _ []string) error {
	login, err := ReadLine("Login: ")
	if err != nil {
		return err
	}
	if login == "" {
		return fmt.Errorf("login cannot be empty")
	}

	password, err := ReadPassword("Password: ")
	if err != nil {
		return err
	}
	defer ZeroBytes(password)

	authKey := crypto.DeriveAuthKey(password, login)
	defer ZeroBytes(authKey)

	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	conn, err := grpcclient.Dial(cfg.ServerAddr, cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer conn.Close()

	resp, err := conn.Auth.Login(cmd.Context(), &pb.LoginRequest{
		Login:   login,
		AuthKey: authKey,
	})
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	sess := &storage.Session{
		Login:        login,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt.AsTime(),
	}
	if err := storage.NewSessionStore(db).Save(cmd.Context(), sess); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	fmt.Printf("Logged in as %q\n", login)
	return nil
}
