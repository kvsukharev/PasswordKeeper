package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd creates the `version` subcommand.
func newVersionCmd(buildVersion, buildDate, buildCommit string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, build date and commit hash",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("passwordkeeper %s (built %s, commit %s)\n",
				buildVersion, buildDate, buildCommit)
		},
	}
}
