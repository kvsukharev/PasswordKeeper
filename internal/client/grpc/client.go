package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
)

// Conn wraps a gRPC connection and exposes typed service clients.
type Conn struct {
	conn *grpc.ClientConn
	// Auth is the AuthService client.
	Auth pb.AuthServiceClient
	// Secrets is the SecretService client.
	Secrets pb.SecretServiceClient
	// Sync is the SyncService client.
	Sync pb.SyncServiceClient
}

// Dial creates a gRPC connection to addr with TLS credentials.
// If caCertFile is non-empty the CA cert is loaded from that file; otherwise
// the system certificate pool is used.
func Dial(addr, caCertFile string) (*Conn, error) {
	creds, err := buildTLS(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("build TLS credentials: %w", err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return &Conn{
		conn:    conn,
		Auth:    pb.NewAuthServiceClient(conn),
		Secrets: pb.NewSecretServiceClient(conn),
		Sync:    pb.NewSyncServiceClient(conn),
	}, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// AuthCtx returns ctx with the Bearer access token added to outgoing metadata.
func AuthCtx(ctx context.Context, accessToken string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
}

// buildTLS constructs gRPC transport credentials.
func buildTLS(caCertFile string) (credentials.TransportCredentials, error) {
	var certPool *x509.CertPool

	if caCertFile != "" {
		caPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %q: %w", caCertFile, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("invalid CA cert in %q", caCertFile)
		}
	} else {
		var err error
		certPool, err = x509.SystemCertPool()
		if err != nil {
			// Fallback to empty pool on platforms where system pool is unavailable.
			certPool = x509.NewCertPool()
		}
	}

	tlsCfg := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}
	return credentials.NewTLS(tlsCfg), nil
}
