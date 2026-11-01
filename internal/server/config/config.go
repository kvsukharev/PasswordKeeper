package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// Config holds all runtime configuration for the server.
type Config struct {
	// GRPCAddr is the TCP address the gRPC server listens on (e.g. ":9090").
	GRPCAddr string
	// DatabaseDSN is the PostgreSQL connection string.
	DatabaseDSN string
	// TLSCertFile is the path to the TLS certificate (PEM).
	TLSCertFile string
	// TLSKeyFile is the path to the TLS private key (PEM).
	TLSKeyFile string
	// JWTSecret is the HMAC-SHA256 signing secret for access tokens.
	JWTSecret string
	// MaxBinaryMB is the maximum allowed size of a binary secret in mebibytes.
	MaxBinaryMB int64
	// AccessTTLMin is the access-token lifetime in minutes.
	AccessTTLMin int
	// RefreshTTLDays is the refresh-token lifetime in days.
	RefreshTTLDays int
	// LoginRateRPS is the sustained per-IP request rate allowed for Login and
	// Register, in requests per second.
	LoginRateRPS float64
	// LoginRateBurst is the maximum burst size for the Login/Register rate limiter.
	LoginRateBurst int
}

const (
	defaultGRPCAddr       = ":9090"
	defaultMaxBinaryMB    = 50
	defaultAccessTTLMin   = 15
	defaultRefreshTTLDay  = 30
	defaultLoginRateRPS   = 5.0
	defaultLoginRateBurst = 10
)

// RegisterFlags adds all server flags to cmd and returns a Load function bound
// to those flags.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().String("addr", defaultGRPCAddr, "gRPC listen address [$PASSWORDKEEPER_GRPC_ADDR]")
	cmd.Flags().String("dsn", "", "PostgreSQL DSN [$PASSWORDKEEPER_DATABASE_DSN]")
	cmd.Flags().String("tls-cert", "", "TLS certificate file [$PASSWORDKEEPER_TLS_CERT]")
	cmd.Flags().String("tls-key", "", "TLS private key file [$PASSWORDKEEPER_TLS_KEY]")
	cmd.Flags().String("jwt-secret", "", "JWT signing secret [$PASSWORDKEEPER_JWT_SECRET]")
	cmd.Flags().Int64("max-binary-mb", defaultMaxBinaryMB,
		"Max binary secret size in MiB [$PASSWORDKEEPER_MAX_BINARY_MB]")
	cmd.Flags().Float64("login-rate-rps", defaultLoginRateRPS,
		"Sustained rate limit for Login/Register per IP in req/s [$PASSWORDKEEPER_LOGIN_RATE_RPS]")
	cmd.Flags().Int("login-rate-burst", defaultLoginRateBurst,
		"Burst size for Login/Register rate limiter [$PASSWORDKEEPER_LOGIN_RATE_BURST]")
}

// Load reads configuration from cmd flags with fallback to environment variables.
func Load(cmd *cobra.Command) (*Config, error) {
	cfg := &Config{
		GRPCAddr:       flagOrEnv(cmd, "addr", "PASSWORDKEEPER_GRPC_ADDR", defaultGRPCAddr),
		DatabaseDSN:    flagOrEnv(cmd, "dsn", "PASSWORDKEEPER_DATABASE_DSN", ""),
		TLSCertFile:    flagOrEnv(cmd, "tls-cert", "PASSWORDKEEPER_TLS_CERT", ""),
		TLSKeyFile:     flagOrEnv(cmd, "tls-key", "PASSWORDKEEPER_TLS_KEY", ""),
		JWTSecret:      flagOrEnv(cmd, "jwt-secret", "PASSWORDKEEPER_JWT_SECRET", ""),
		MaxBinaryMB:    int64OrEnv(cmd, "max-binary-mb", "PASSWORDKEEPER_MAX_BINARY_MB", defaultMaxBinaryMB),
		AccessTTLMin:   defaultAccessTTLMin,
		RefreshTTLDays: defaultRefreshTTLDay,
		LoginRateRPS:   float64OrEnv(cmd, "login-rate-rps", "PASSWORDKEEPER_LOGIN_RATE_RPS", defaultLoginRateRPS),
		LoginRateBurst: intOrEnv(cmd, "login-rate-burst", "PASSWORDKEEPER_LOGIN_RATE_BURST", defaultLoginRateBurst),
	}
	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if c.DatabaseDSN == "" {
		return fmt.Errorf("database DSN is required (--dsn or PASSWORDKEEPER_DATABASE_DSN)")
	}
	if c.TLSCertFile == "" {
		return fmt.Errorf("TLS cert file is required (--tls-cert or PASSWORDKEEPER_TLS_CERT)")
	}
	if c.TLSKeyFile == "" {
		return fmt.Errorf("TLS key file is required (--tls-key or PASSWORDKEEPER_TLS_KEY)")
	}
	if c.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required (--jwt-secret or PASSWORDKEEPER_JWT_SECRET)")
	}
	return nil
}

// flagOrEnv returns the flag value if explicitly set, then the env var, then the fallback.
func flagOrEnv(cmd *cobra.Command, flag, envKey, fallback string) string {
	if f := cmd.Flags().Lookup(flag); f != nil && f.Changed {
		return f.Value.String()
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}

// int64OrEnv is like flagOrEnv but for int64 values.
func int64OrEnv(cmd *cobra.Command, flag, envKey string, fallback int64) int64 {
	if f := cmd.Flags().Lookup(flag); f != nil && f.Changed {
		if v, err := strconv.ParseInt(f.Value.String(), 10, 64); err == nil {
			return v
		}
	}
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

// intOrEnv is like flagOrEnv but for int values.
func intOrEnv(cmd *cobra.Command, flag, envKey string, fallback int) int {
	if f := cmd.Flags().Lookup(flag); f != nil && f.Changed {
		if v, err := strconv.Atoi(f.Value.String()); err == nil {
			return v
		}
	}
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// float64OrEnv is like flagOrEnv but for float64 values.
func float64OrEnv(cmd *cobra.Command, flag, envKey string, fallback float64) float64 {
	if f := cmd.Flags().Lookup(flag); f != nil && f.Changed {
		if v, err := strconv.ParseFloat(f.Value.String(), 64); err == nil {
			return v
		}
	}
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return fallback
}
