package grpc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
)

// selfSignedCA generates a minimal self-signed CA certificate and returns its PEM bytes.
func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestDial_SystemPool(t *testing.T) {
	// grpc.NewClient is lazy — no actual connection is made, so this succeeds
	// even if no server is listening.
	conn, err := grpcclient.Dial("localhost:19090", "")
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.NoError(t, conn.Close())
}

func TestDial_CustomCA_Valid(t *testing.T) {
	pemBytes := selfSignedCA(t)
	f := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(f, pemBytes, 0600))

	conn, err := grpcclient.Dial("localhost:19091", f)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.NoError(t, conn.Close())
}

func TestDial_CustomCA_Nonexistent(t *testing.T) {
	_, err := grpcclient.Dial("localhost:19092", "/nonexistent/path/ca.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build TLS credentials")
}

func TestDial_CustomCA_InvalidPEM(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(f, []byte("not a pem block"), 0600))

	_, err := grpcclient.Dial("localhost:19093", f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CA cert")
}

func TestAuthCtx_AddsBearer(t *testing.T) {
	ctx := grpcclient.AuthCtx(context.Background(), "mytoken123")
	md, ok := metadata.FromOutgoingContext(ctx)
	require.True(t, ok)
	vals := md.Get("authorization")
	require.Len(t, vals, 1)
	assert.Equal(t, "Bearer mytoken123", vals[0])
}
