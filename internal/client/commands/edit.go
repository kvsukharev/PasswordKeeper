package commands

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/client/validator"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit an existing secret",
		Args:  cobra.ExactArgs(1),
		RunE:  runEdit,
	}
	cmd.Flags().StringArray("meta", nil, "Replace metadata with key:value pair (repeatable)")
	cmd.Flags().String("note", "", "Replace the free-text note")
	return cmd
}

func runEdit(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	sessionStore := storage.NewSessionStore(db)
	sess, err := sessionStore.Load(cmd.Context())
	if err != nil {
		return err
	}

	secrets := storage.NewSecretStore(db)
	sec, err := secrets.GetByName(cmd.Context(), args[0])
	if err != nil {
		return fmt.Errorf("secret %q not found in local cache", args[0])
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

	var current model.Payload
	if unmarshalErr := json.Unmarshal(plaintext, &current); unmarshalErr != nil {
		return fmt.Errorf("parse payload: %w", unmarshalErr)
	}

	fmt.Printf("Editing %q (%s)\n\n", sec.Name, string(sec.Type))

	newName, err := ReadLineWithDefault("Name", sec.Name)
	if err != nil {
		return err
	}

	updated, err := promptEditPayload(sec.Type, &current)
	if err != nil {
		return err
	}

	metaFlags, _ := cmd.Flags().GetStringArray("meta")
	note, _ := cmd.Flags().GetString("note")
	if len(metaFlags) > 0 || note != "" {
		updated.Meta = parseMeta(metaFlags, note)
	} else {
		updated.Meta = current.Meta
	}

	jsonBytes, err := json.Marshal(updated)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	newAAD := crypto.MakeAAD(sec.ID, string(sec.Type))
	encrypted, err := crypto.Encrypt(encKey, jsonBytes, newAAD)
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}

	conn, err := grpcclient.Dial(cfg.ServerAddr, cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer conn.Close()

	ctx := cmd.Context()
	if refreshErr := refreshSessionIfNeeded(ctx, conn, sessionStore, sess); refreshErr != nil {
		return refreshErr
	}

	authCtx := grpcclient.AuthCtx(ctx, sess.AccessToken)
	meta, err := conn.Secrets.Update(authCtx, &pb.UpdateSecretRequest{
		Id:          sec.ID,
		Name:        newName,
		Payload:     encrypted,
		BaseVersion: sec.Version,
	})
	if err != nil {
		if isOfflineError(err) {
			pending := storage.NewPendingStore(db)
			_ = pending.Enqueue(ctx, &storage.PendingChange{
				ID:          sec.ID,
				Action:      "update",
				Type:        sec.Type,
				Name:        newName,
				Payload:     encrypted,
				BaseVersion: sec.Version,
			})
			_ = secrets.Upsert(ctx, &storage.LocalSecret{
				ID:        sec.ID,
				Type:      sec.Type,
				Name:      newName,
				Payload:   encrypted,
				Version:   sec.Version,
				UpdatedAt: time.Now(),
			})
			fmt.Printf("Offline: edit of %q queued for next sync.\n", newName)
			return nil
		}
		return fmt.Errorf("update secret: %w", err)
	}

	if err := secrets.Upsert(ctx, &storage.LocalSecret{
		ID:        sec.ID,
		Type:      sec.Type,
		Name:      newName,
		Payload:   encrypted,
		Version:   meta.GetVersion(),
		UpdatedAt: meta.GetUpdatedAt().AsTime(),
	}); err != nil {
		return fmt.Errorf("update local cache: %w", err)
	}

	fmt.Printf("Secret %q updated (version %d)\n", newName, meta.GetVersion())
	return nil
}

// promptEditPayload prompts for each field of the given type with the current
// value shown as a default. Pressing Enter without input keeps the current value.
func promptEditPayload(t model.SecretType, current *model.Payload) (*model.Payload, error) {
	updated := &model.Payload{}
	switch t {
	case model.SecretTypeCredentials:
		c := current.Credentials
		if c == nil {
			c = &model.CredentialsPayload{}
		}
		login, err := ReadLineWithDefault("Login", c.Login)
		if err != nil {
			return nil, err
		}
		pw, err := ReadPasswordOptional("Password [keep current]: ")
		if err != nil {
			return nil, err
		}
		password := c.Password
		if len(pw) > 0 {
			password = string(pw)
			ZeroBytes(pw)
		}
		url, err := ReadLineWithDefault("URL", c.URL)
		if err != nil {
			return nil, err
		}
		updated.Credentials = &model.CredentialsPayload{
			Login:    login,
			Password: password,
			URL:      url,
		}

	case model.SecretTypeText:
		c := current.Text
		if c == nil {
			c = &model.TextPayload{}
		}
		content, err := ReadLineWithDefault("Content", c.Content)
		if err != nil {
			return nil, err
		}
		updated.Text = &model.TextPayload{Content: content}

	case model.SecretTypeCard:
		c := current.Card
		if c == nil {
			c = &model.CardPayload{}
		}
		number, err := ReadLineWithDefault("Card number", c.Number)
		if err != nil {
			return nil, err
		}
		if number != c.Number && !validator.LuhnCheck(number) {
			return nil, fmt.Errorf("invalid card number (failed Luhn check)")
		}
		holder, err := ReadLineWithDefault("Holder name", c.Holder)
		if err != nil {
			return nil, err
		}
		expiry, err := ReadLineWithDefault("Expiry (MM/YY)", c.Expiry)
		if err != nil {
			return nil, err
		}
		if expiry != c.Expiry {
			if expiryErr := validator.ValidateExpiry(expiry); expiryErr != nil {
				return nil, expiryErr
			}
		}
		cvv, err := ReadLineWithDefault("CVV", c.CVV)
		if err != nil {
			return nil, err
		}
		if cvv != c.CVV {
			if cvvErr := validator.ValidateCVV(cvv); cvvErr != nil {
				return nil, cvvErr
			}
		}
		updated.Card = &model.CardPayload{
			Number: number,
			Holder: holder,
			Expiry: expiry,
			CVV:    cvv,
		}

	default:
		return current, nil
	}
	return updated, nil
}
