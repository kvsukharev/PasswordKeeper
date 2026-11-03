package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRootCmd_HasSubcommands(t *testing.T) {
	root := NewRootCmd("1.0.0", "2024-01-01", "abc1234")
	require.NotNil(t, root)

	names := make(map[string]bool)
	for _, sub := range root.Commands() {
		names[sub.Name()] = true
	}

	for _, expected := range []string{
		"version", "register", "login", "logout",
		"add", "list", "get", "edit", "delete",
		"upload", "download", "sync",
	} {
		assert.True(t, names[expected], "missing subcommand: %s", expected)
	}
}

func TestVersionCmd_NoError(t *testing.T) {
	root := NewRootCmd("2.3.4", "2024-06-01", "deadbeef")
	root.SetArgs([]string{"version"})
	require.NoError(t, root.Execute())
}
