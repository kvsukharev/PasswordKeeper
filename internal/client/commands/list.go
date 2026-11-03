package commands

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secrets from the local cache",
		RunE:  runList,
	}
}

func runList(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = storage.NewSessionStore(db).Load(cmd.Context())
	if err != nil {
		return err
	}

	secrets := storage.NewSecretStore(db)
	items, err := secrets.List(cmd.Context())
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}

	if len(items) == 0 {
		fmt.Println("No secrets found. Use 'passwordkeeper add' to create one.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tVERSION\tUPDATED")
	for _, s := range items {
		name := s.Name
		if s.IsConflict {
			name += " [!]"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n",
			name,
			string(s.Type),
			s.Version,
			s.UpdatedAt.Format("2006-01-02"),
		)
	}
	return w.Flush()
}
