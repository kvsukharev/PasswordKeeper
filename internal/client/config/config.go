package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const (
	defaultServerAddr = "localhost:9090"
)

// Config holds all runtime configuration for the CLI client.
type Config struct {
	// ServerAddr is the host:port of the PasswordKeeper gRPC server.
	ServerAddr string
	// CACertFile is the optional path to the CA certificate used to verify the
	// server's TLS certificate. When empty the system cert pool is used.
	CACertFile string
	// DataDir is the directory where the local SQLite cache is stored.
	DataDir string
}

// RegisterFlags adds persistent client flags to cmd.
func RegisterFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("server", defaultServerAddr,
		"server address [$PASSWORDKEEPER_SERVER]")
	cmd.PersistentFlags().String("ca-cert", "",
		"path to CA certificate file [$PASSWORDKEEPER_CA_CERT]")
	cmd.PersistentFlags().String("data-dir", "",
		"local data directory [$PASSWORDKEEPER_DATA_DIR]")
}

// Load reads configuration from cmd's persistent flags with env-var fallback.
func Load(cmd *cobra.Command) (*Config, error) {
	cfg := &Config{
		ServerAddr: flagOrEnv(cmd, "server", "PASSWORDKEEPER_SERVER", defaultServerAddr),
		CACertFile: flagOrEnv(cmd, "ca-cert", "PASSWORDKEEPER_CA_CERT", ""),
		DataDir:    flagOrEnv(cmd, "data-dir", "PASSWORDKEEPER_DATA_DIR", ""),
	}

	if cfg.DataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("resolve data directory: %w", err)
		}
		cfg.DataDir = filepath.Join(base, "passwordkeeper")
	}

	return cfg, nil
}

// flagOrEnv returns the flag value if changed, then the env var, then fallback.
func flagOrEnv(cmd *cobra.Command, flag, env, fallback string) string {
	if f := cmd.Flags().Lookup(flag); f == nil {
		if f2 := cmd.InheritedFlags().Lookup(flag); f2 != nil && f2.Changed {
			return f2.Value.String()
		}
	} else if f.Changed {
		return f.Value.String()
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}
