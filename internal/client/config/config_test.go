package config_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/config"
)

func TestLoad_Defaults(t *testing.T) {
	cmd := &cobra.Command{}
	config.RegisterFlags(cmd)

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.Equal(t, "localhost:9090", cfg.ServerAddr)
	assert.Equal(t, "", cfg.CACertFile)
	assert.NotEmpty(t, cfg.DataDir)
}

func TestLoad_FlagOverride(t *testing.T) {
	cmd := &cobra.Command{}
	config.RegisterFlags(cmd)
	require.NoError(t, cmd.ParseFlags([]string{
		"--server", "myserver:8080",
		"--ca-cert", "/tmp/ca.pem",
		"--data-dir", "/tmp/testdata",
	}))

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.Equal(t, "myserver:8080", cfg.ServerAddr)
	assert.Equal(t, "/tmp/ca.pem", cfg.CACertFile)
	assert.Equal(t, "/tmp/testdata", cfg.DataDir)
}

func TestLoad_EnvVarFallback(t *testing.T) {
	t.Setenv("PASSWORDKEEPER_SERVER", "envserver:1234")
	t.Setenv("PASSWORDKEEPER_DATA_DIR", "/tmp/envdata")

	cmd := &cobra.Command{}
	config.RegisterFlags(cmd)

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.Equal(t, "envserver:1234", cfg.ServerAddr)
	assert.Equal(t, "/tmp/envdata", cfg.DataDir)
}
