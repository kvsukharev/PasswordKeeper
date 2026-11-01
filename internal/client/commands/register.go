package commands

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

// newRegisterCmd creates the `register` subcommand.
func newRegisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "register",
		Short: "Create a new account on the server",
		RunE:  runRegister,
	}
}

func runRegister(cmd *cobra.Command, _ []string) error {
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

	confirm, err := ReadPassword("Confirm password: ")
	if err != nil {
		return err
	}
	defer ZeroBytes(confirm)

	if !bytes.Equal(password, confirm) {
		return fmt.Errorf("passwords do not match")
	}

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

	resp, err := conn.Auth.Register(cmd.Context(), &pb.RegisterRequest{
		Login:   login,
		AuthKey: authKey,
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
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

	fmt.Printf("Registered and logged in as %q\n", login)
	return nil
}
