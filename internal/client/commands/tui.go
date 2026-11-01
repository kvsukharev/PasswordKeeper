package commands

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/client/tui"
)

// newTUICmd returns the cobra command that launches the terminal UI.
func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal user interface",
		RunE:  runTUI,
	}
}

func runTUI(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	sess, err := storage.NewSessionStore(db).Load(cmd.Context())
	if err != nil {
		return err
	}

	secrets, err := storage.NewSecretStore(db).List(cmd.Context())
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}

	masterPwd, err := ReadPassword("Master password: ")
	if err != nil {
		return err
	}
	encKey := crypto.DeriveEncKey(masterPwd, sess.Login)
	ZeroBytes(masterPwd)

	m := tui.New(secrets, sess.Login, encKey)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}
