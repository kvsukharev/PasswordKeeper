package config_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/server/config"
)

func newCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	config.RegisterFlags(cmd)
	return cmd
}

func validFlags() []string {
	return []string{
		"--dsn", "postgres://localhost/test",
		"--tls-cert", "/tmp/cert.pem",
		"--tls-key", "/tmp/key.pem",
		"--jwt-secret", "supersecret",
	}
}

func TestLoad_Defaults(t *testing.T) {
	cmd := newCmd(t)
	require.NoError(t, cmd.ParseFlags(validFlags()))

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.Equal(t, ":9090", cfg.GRPCAddr)
	assert.Equal(t, int64(50), cfg.MaxBinaryMB)
	assert.Equal(t, 15, cfg.AccessTTLMin)
	assert.Equal(t, 30, cfg.RefreshTTLDays)
}

func TestLoad_FlagOverride(t *testing.T) {
	cmd := newCmd(t)
	flags := append(validFlags(),
		"--addr", ":8080",
		"--max-binary-mb", "100",
	)
	require.NoError(t, cmd.ParseFlags(flags))

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.GRPCAddr)
	assert.Equal(t, int64(100), cfg.MaxBinaryMB)
}

func TestLoad_EnvFallback(t *testing.T) {
	t.Setenv("PASSWORDKEEPER_GRPC_ADDR", "0.0.0.0:9999")
	t.Setenv("PASSWORDKEEPER_DATABASE_DSN", "postgres://envhost/db")
	t.Setenv("PASSWORDKEEPER_TLS_CERT", "/tmp/cert")
	t.Setenv("PASSWORDKEEPER_TLS_KEY", "/tmp/key")
	t.Setenv("PASSWORDKEEPER_JWT_SECRET", "env-secret")
	t.Setenv("PASSWORDKEEPER_MAX_BINARY_MB", "200")

	cmd := newCmd(t)
	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9999", cfg.GRPCAddr)
	assert.Equal(t, int64(200), cfg.MaxBinaryMB)
}

func TestLoad_MissingDSN(t *testing.T) {
	cmd := newCmd(t)
	require.NoError(t, cmd.ParseFlags([]string{
		"--tls-cert", "/tmp/cert.pem",
		"--tls-key", "/tmp/key.pem",
		"--jwt-secret", "s",
	}))

	_, err := config.Load(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database DSN")
}

func TestLoad_MissingTLSCert(t *testing.T) {
	cmd := newCmd(t)
	require.NoError(t, cmd.ParseFlags([]string{
		"--dsn", "postgres://x",
		"--tls-key", "/tmp/key.pem",
		"--jwt-secret", "s",
	}))

	_, err := config.Load(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS cert")
}

func TestLoad_MissingTLSKey(t *testing.T) {
	cmd := newCmd(t)
	require.NoError(t, cmd.ParseFlags([]string{
		"--dsn", "postgres://x",
		"--tls-cert", "/tmp/cert.pem",
		"--jwt-secret", "s",
	}))

	_, err := config.Load(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS key")
}

func TestLoad_MissingJWTSecret(t *testing.T) {
	cmd := newCmd(t)
	require.NoError(t, cmd.ParseFlags([]string{
		"--dsn", "postgres://x",
		"--tls-cert", "/tmp/cert.pem",
		"--tls-key", "/tmp/key.pem",
	}))

	_, err := config.Load(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT secret")
}

func TestLoad_RateLimitFlags(t *testing.T) {
	cmd := newCmd(t)
	flags := append(validFlags(),
		"--login-rate-rps", "2.5",
		"--login-rate-burst", "20",
	)
	require.NoError(t, cmd.ParseFlags(flags))

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.InDelta(t, 2.5, cfg.LoginRateRPS, 0.001)
	assert.Equal(t, 20, cfg.LoginRateBurst)
}

func TestLoad_RateLimitEnv(t *testing.T) {
	t.Setenv("PASSWORDKEEPER_LOGIN_RATE_RPS", "3.0")
	t.Setenv("PASSWORDKEEPER_LOGIN_RATE_BURST", "15")
	t.Setenv("PASSWORDKEEPER_DATABASE_DSN", "postgres://envhost/db")
	t.Setenv("PASSWORDKEEPER_TLS_CERT", "/tmp/cert")
	t.Setenv("PASSWORDKEEPER_TLS_KEY", "/tmp/key")
	t.Setenv("PASSWORDKEEPER_JWT_SECRET", "env-secret")

	cmd := newCmd(t)
	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.InDelta(t, 3.0, cfg.LoginRateRPS, 0.001)
	assert.Equal(t, 15, cfg.LoginRateBurst)
}

func TestLoad_RateLimitDefaults(t *testing.T) {
	cmd := newCmd(t)
	require.NoError(t, cmd.ParseFlags(validFlags()))

	cfg, err := config.Load(cmd)
	require.NoError(t, err)
	assert.InDelta(t, 5.0, cfg.LoginRateRPS, 0.001)
	assert.Equal(t, 10, cfg.LoginRateBurst)
}
