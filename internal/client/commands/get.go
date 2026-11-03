package commands

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Decrypt and display a secret from the local cache",
		Args:  cobra.ExactArgs(1),
		RunE:  runGet,
	}
	cmd.Flags().Bool("show", false, "Reveal sensitive values (passwords, CVV)")
	return cmd
}

func runGet(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	sess, err := storage.NewSessionStore(db).Load(cmd.Context())
	if err != nil {
		return err
	}

	sec, err := storage.NewSecretStore(db).GetByName(cmd.Context(), args[0])
	if err != nil {
		return fmt.Errorf("secret %q not found in local cache (run 'list' to see available secrets)", args[0])
	}

	masterPwd, err := ReadPassword("Master password: ")
	if err != nil {
		return err
	}
	encKey := crypto.DeriveEncKey(masterPwd, sess.Login)
	ZeroBytes(masterPwd)
	defer ZeroBytes(encKey)

	aad := crypto.MakeAAD(sec.ID, string(sec.Type))
	plaintext, err := crypto.Decrypt(encKey, sec.Payload, aad)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong master password?): %w", err)
	}

	var payload model.Payload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	show, _ := cmd.Flags().GetBool("show")
	printPayload(cmd.OutOrStdout(), sec.Name, sec.Type, sec.Version, &payload, show)
	return nil
}

func printPayload(out io.Writer, name string, t model.SecretType, version int64, p *model.Payload, show bool) {
	fmt.Fprintf(out, "Name:    %s\n", name)
	fmt.Fprintf(out, "Type:    %s\n", string(t))
	fmt.Fprintf(out, "Version: %d\n\n", version)

	mask := func(v string) string {
		if show {
			return v
		}
		return "*** (use --show to reveal)"
	}

	switch t {
	case model.SecretTypeCredentials:
		if p.Credentials != nil {
			fmt.Fprintf(out, "Login:    %s\n", p.Credentials.Login)
			fmt.Fprintf(out, "Password: %s\n", mask(p.Credentials.Password))
			if p.Credentials.URL != "" {
				fmt.Fprintf(out, "URL:      %s\n", p.Credentials.URL)
			}
		}
	case model.SecretTypeText:
		if p.Text != nil {
			fmt.Fprintf(out, "Content:\n%s\n", p.Text.Content)
		}
	case model.SecretTypeCard:
		if p.Card != nil {
			fmt.Fprintf(out, "Number: %s\n", p.Card.Number)
			fmt.Fprintf(out, "Holder: %s\n", p.Card.Holder)
			fmt.Fprintf(out, "Expiry: %s\n", p.Card.Expiry)
			fmt.Fprintf(out, "CVV:    %s\n", mask(p.Card.CVV))
		}
	case model.SecretTypeOTP:
		if p.OTP != nil {
			fmt.Fprintf(out, "Issuer:    %s\n", p.OTP.Issuer)
			fmt.Fprintf(out, "Account:   %s\n", p.OTP.Account)
			fmt.Fprintf(out, "Secret:    %s\n", mask(p.OTP.Secret))
			fmt.Fprintf(out, "Algorithm: %s\n", p.OTP.Algorithm)
			fmt.Fprintf(out, "Digits:    %d\n", p.OTP.Digits)
			fmt.Fprintf(out, "Period:    %ds\n", p.OTP.Period)
			fmt.Fprintf(out, "\nUse 'passwordkeeper otp %s' to generate the current code.\n", name)
		}
	default:
		fmt.Fprintf(out, "(encrypted binary — use 'download' to export)\n")
	}

	if len(p.Meta.Pairs) > 0 || p.Meta.Note != "" {
		fmt.Fprintln(out)
		for _, kv := range p.Meta.Pairs {
			fmt.Fprintf(out, "%s: %s\n", kv.Key, kv.Value)
		}
		if p.Meta.Note != "" {
			fmt.Fprintf(out, "Note: %s\n", p.Meta.Note)
		}
	}
}
