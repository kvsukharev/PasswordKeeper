package commands

import (
	"context"
	"fmt"
	"time"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// refreshSessionIfNeeded auto-refreshes the access token when it is within 30
// seconds of expiry. It updates the local session store and mutates sess in place.
func refreshSessionIfNeeded(
	ctx context.Context,
	conn *grpcclient.Conn,
	store *storage.SessionStore,
	sess *storage.Session,
) error {
	if !time.Now().After(sess.ExpiresAt.Add(-30 * time.Second)) {
		return nil
	}
	resp, err := conn.Auth.Refresh(ctx, &pb.RefreshRequest{
		RefreshToken: sess.RefreshToken,
	})
	if err != nil {
		return fmt.Errorf("session expired, please run 'passwordkeeper login': %w", err)
	}
	sess.AccessToken = resp.AccessToken
	sess.RefreshToken = resp.RefreshToken
	sess.ExpiresAt = resp.ExpiresAt.AsTime()
	return store.UpdateTokens(ctx, sess.AccessToken, sess.RefreshToken, sess.ExpiresAt)
}

// parseSecretType converts a user-supplied type string to proto and model values.
func parseSecretType(s string) (pb.SecretType, model.SecretType, error) {
	switch s {
	case "credentials", "creds":
		return pb.SecretType_SECRET_TYPE_CREDENTIALS, model.SecretTypeCredentials, nil
	case "text":
		return pb.SecretType_SECRET_TYPE_TEXT, model.SecretTypeText, nil
	case "card":
		return pb.SecretType_SECRET_TYPE_CARD, model.SecretTypeCard, nil
	case "otp":
		return pb.SecretType_SECRET_TYPE_OTP, model.SecretTypeOTP, nil
	default:
		return 0, "", fmt.Errorf("unknown type %q: use credentials, text, card, or otp", s)
	}
}

// parseMeta converts --meta key:value flags and --note into a model.Metadata.
func parseMeta(flags []string, note string) model.Metadata {
	pairs := make([]model.MetaPair, 0, len(flags))
	for _, f := range flags {
		for i, c := range f {
			if c == ':' {
				pairs = append(pairs, model.MetaPair{Key: f[:i], Value: f[i+1:]})
				break
			}
		}
	}
	return model.Metadata{Pairs: pairs, Note: note}
}
