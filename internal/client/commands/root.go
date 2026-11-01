package commands

import (
	"github.com/spf13/cobra"

	"github.com/kvsuharev/passwordkeeper/internal/client/config"
)

// NewRootCmd builds and returns the root cobra command for the CLI.
func NewRootCmd(buildVersion, buildDate, buildCommit string) *cobra.Command {
	root := &cobra.Command{
		Use:           "passwordkeeper",
		Short:         "PasswordKeeper — zero-knowledge password manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	config.RegisterFlags(root)

	root.AddCommand(newVersionCmd(buildVersion, buildDate, buildCommit))
	root.AddCommand(newRegisterCmd())
	root.AddCommand(newLoginCmd())
	root.AddCommand(newLogoutCmd())
	root.AddCommand(newAddCmd())
	root.AddCommand(newListCmd())
	root.AddCommand(newGetCmd())
	root.AddCommand(newEditCmd())
	root.AddCommand(newDeleteCmd())
	root.AddCommand(newUploadCmd())
	root.AddCommand(newDownloadCmd())
	root.AddCommand(newSyncCmd())
	root.AddCommand(newOtpCmd())
	root.AddCommand(newTUICmd())

	return root
}
