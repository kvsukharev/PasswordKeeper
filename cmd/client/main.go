// Command passwordkeeper is the PasswordKeeper CLI client.
// It encrypts secrets locally and synchronises them with the passwordkeeper-server
// over gRPC/TLS.
package main

import (
	"log/slog"
	"os"

	"github.com/kvsuharev/passwordkeeper/internal/client/commands"
)

// build-time variables injected via -ldflags.
var (
	buildVersion = "N/A"
	buildDate    = "N/A"
	buildCommit  = "N/A"
)

func main() {
	root := commands.NewRootCmd(buildVersion, buildDate, buildCommit)

	if err := root.Execute(); err != nil {
		slog.Error("error", "msg", err)
		os.Exit(1)
	}
}
