// Command passwordkeeper-server is the PasswordKeeper gRPC server.
// It exposes AuthService, SecretService and SyncService over TLS and persists
// data in PostgreSQL.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/server/auth"
	"github.com/kvsuharev/passwordkeeper/internal/server/config"
	"github.com/kvsuharev/passwordkeeper/internal/server/service"
	"github.com/kvsuharev/passwordkeeper/internal/server/storage"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

// build-time variables injected via -ldflags.
var (
	buildVersion = "N/A"
	buildDate    = "N/A"
	buildCommit  = "N/A"
)

func main() {
	root := &cobra.Command{
		Use:           "passwordkeeper-server",
		Short:         "PasswordKeeper gRPC server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(versionCmd())
	root.AddCommand(serveCmd())

	if err := root.Execute(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, build date and commit",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("passwordkeeper-server %s (built %s, commit %s)\n",
				buildVersion, buildDate, buildCommit)
		},
	}
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gRPC server",
		RunE:  runServe,
	}
	config.RegisterFlags(cmd)
	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(cmd)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Graceful shutdown: cancel ctx on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Schema migrations.
	slog.Info("running migrations")
	err = storage.RunMigrations(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	// Database connection pool.
	pool, err := storage.NewPool(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	slog.Info("database connected")

	// Repositories.
	userRepo := storage.NewUserRepo(pool)
	tokenRepo := storage.NewTokenRepo(pool)
	secretRepo := storage.NewSecretRepo(pool)

	// Token manager.
	tokenMgr := auth.NewManager(
		cfg.JWTSecret,
		time.Duration(cfg.AccessTTLMin)*time.Minute,
		time.Duration(cfg.RefreshTTLDays)*24*time.Hour,
	)

	// Services.
	authSvc := service.NewAuthService(userRepo, tokenRepo, tokenMgr)
	secretSvc := service.NewSecretService(secretRepo)
	syncSvc := service.NewSyncService(secretRepo, secretSvc)

	// TLS credentials.
	tlsCreds, err := loadTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("load TLS: %w", err)
	}

	// Rate limiter for Login and Register (cleanup goroutine tied to server lifetime).
	rateLimiter := transport.NewRateLimiter(ctx, cfg.LoginRateRPS, cfg.LoginRateBurst)

	// gRPC server.
	maxMsgBytes := int(cfg.MaxBinaryMB) * 1024 * 1024
	grpcSrv := grpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.MaxRecvMsgSize(maxMsgBytes),
		grpc.MaxSendMsgSize(maxMsgBytes),
		grpc.ChainUnaryInterceptor(
			loggingUnaryInterceptor(logger),
			transport.RateLimitUnaryInterceptor(rateLimiter),
			transport.AuthUnaryInterceptor(tokenMgr),
		),
		grpc.ChainStreamInterceptor(
			loggingStreamInterceptor(logger),
			transport.AuthStreamInterceptor(tokenMgr),
		),
	)

	// Register services.
	pb.RegisterAuthServiceServer(grpcSrv, transport.NewAuthHandler(authSvc))
	pb.RegisterSecretServiceServer(grpcSrv, transport.NewSecretHandler(secretSvc, int64(cfg.MaxBinaryMB)*1024*1024))
	pb.RegisterSyncServiceServer(grpcSrv, transport.NewSyncHandler(syncSvc))

	// Start listener.
	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.GRPCAddr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("server started", "addr", cfg.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		grpcSrv.GracefulStop()
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	}

	slog.Info("server stopped")
	return nil
}

// loadTLS loads the TLS key pair and returns gRPC server credentials.
func loadTLS(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	return credentials.NewTLS(tlsCfg), nil
}

// loggingUnaryInterceptor logs each unary RPC call with method, duration and error.
func loggingUnaryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		logRPC(log, "rpc", info.FullMethod, time.Since(start), err)
		return resp, err
	}
}

// loggingStreamInterceptor logs each streaming RPC call.
func loggingStreamInterceptor(log *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		logRPC(log, "rpc_stream", info.FullMethod, time.Since(start), err)
		return err
	}
}

// isServerError reports whether a gRPC error code indicates a server-side fault
// (as opposed to a client mistake like bad input or missing auth).
func isServerError(err error) bool {
	switch status.Code(err) {
	case codes.Internal, codes.Unavailable, codes.DataLoss, codes.Unknown:
		return true
	default:
		return false
	}
}

// logRPC emits a structured log entry at Debug level for client errors and at
// Error level for server faults. Successful calls are logged at Debug.
func logRPC(log *slog.Logger, event, method string, dur time.Duration, err error) {
	args := []any{"method", method, "duration", dur}
	if err != nil {
		args = append(args, "error", err)
		if isServerError(err) {
			log.Error(event, args...)
			return
		}
	}
	log.Debug(event, args...)
}
