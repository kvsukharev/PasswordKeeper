package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/client/validator"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

func newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <type>",
		Short: "Add a new secret (type: credentials, text, card, otp)",
		Args:  cobra.ExactArgs(1),
		RunE:  runAdd,
	}
	cmd.Flags().String("name", "", "Secret name (label)")
	cmd.Flags().StringArray("meta", nil, "Metadata key:value pair (repeatable)")
	cmd.Flags().String("note", "", "Free-text note")
	return cmd
}

func runAdd(cmd *cobra.Command, args []string) error {
	typeStr := strings.ToLower(args[0])
	pbType, modelType, err := parseSecretType(typeStr)
	if err != nil {
		return err
	}

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

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		name, err = ReadLine("Name: ")
		if err != nil {
			return err
		}
	}
	if name == "" {
		return fmt.Errorf("name is required")
	}

	masterPwd, err := ReadPassword("Master password: ")
	if err != nil {
		return err
	}
	encKey := crypto.DeriveEncKey(masterPwd, sess.Login)
	ZeroBytes(masterPwd)
	defer ZeroBytes(encKey)

	payload, err := promptNewPayload(modelType)
	if err != nil {
		return err
	}

	metaFlags, _ := cmd.Flags().GetStringArray("meta")
	note, _ := cmd.Flags().GetString("note")
	payload.Meta = parseMeta(metaFlags, note)

	id := uuid.New().String()
	aad := crypto.MakeAAD(id, string(modelType))

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	encrypted, err := crypto.Encrypt(encKey, jsonBytes, aad)
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
	secrets := storage.NewSecretStore(db)
	meta, err := conn.Secrets.Create(authCtx, &pb.CreateSecretRequest{
		Id:      id,
		Type:    pbType,
		Name:    name,
		Payload: encrypted,
	})
	if err != nil {
		if isOfflineError(err) {
			pending := storage.NewPendingStore(db)
			_ = pending.Enqueue(ctx, &storage.PendingChange{
				ID:      id,
				Action:  "create",
				Type:    modelType,
				Name:    name,
				Payload: encrypted,
			})
			_ = secrets.Upsert(ctx, &storage.LocalSecret{
				ID:        id,
				Type:      modelType,
				Name:      name,
				Payload:   encrypted,
				Version:   0,
				UpdatedAt: time.Now(),
			})
			fmt.Printf("Offline: secret %q queued for next sync.\n", name)
			return nil
		}
		return fmt.Errorf("create secret: %w", err)
	}

	if err := secrets.Upsert(ctx, &storage.LocalSecret{
		ID:        id,
		Type:      modelType,
		Name:      name,
		Payload:   encrypted,
		Version:   meta.GetVersion(),
		UpdatedAt: meta.GetUpdatedAt().AsTime(),
	}); err != nil {
		return fmt.Errorf("cache secret: %w", err)
	}

	fmt.Printf("Secret %q added (version %d)\n", name, meta.GetVersion())
	return nil
}

// promptNewPayload interactively collects type-specific fields for a new secret.
func promptNewPayload(t model.SecretType) (*model.Payload, error) {
	payload := &model.Payload{}
	switch t {
	case model.SecretTypeCredentials:
		login, err := ReadLine("Login: ")
		if err != nil {
			return nil, err
		}
		pw, err := ReadPassword("Password: ")
		if err != nil {
			return nil, err
		}
		url, err := ReadLine("URL (optional): ")
		if err != nil {
			ZeroBytes(pw)
			return nil, err
		}
		payload.Credentials = &model.CredentialsPayload{
			Login:    login,
			Password: string(pw),
			URL:      url,
		}
		ZeroBytes(pw)

	case model.SecretTypeText:
		content, err := ReadLine("Content: ")
		if err != nil {
			return nil, err
		}
		payload.Text = &model.TextPayload{Content: content}

	case model.SecretTypeCard:
		number, err := ReadLine("Card number: ")
		if err != nil {
			return nil, err
		}
		if !validator.LuhnCheck(number) {
			return nil, fmt.Errorf("invalid card number (failed Luhn check)")
		}
		holder, err := ReadLine("Holder name: ")
		if err != nil {
			return nil, err
		}
		expiry, err := ReadLine("Expiry (MM/YY): ")
		if err != nil {
			return nil, err
		}
		if expiryErr := validator.ValidateExpiry(expiry); expiryErr != nil {
			return nil, expiryErr
		}
		cvv, err := ReadLine("CVV: ")
		if err != nil {
			return nil, err
		}
		if cvvErr := validator.ValidateCVV(cvv); cvvErr != nil {
			return nil, cvvErr
		}
		payload.Card = &model.CardPayload{
			Number: number,
			Holder: holder,
			Expiry: expiry,
			CVV:    cvv,
		}
	case model.SecretTypeOTP:
		issuer, err := ReadLine("Issuer (e.g. GitHub): ")
		if err != nil {
			return nil, err
		}
		account, err := ReadLine("Account (e.g. alice@example.com): ")
		if err != nil {
			return nil, err
		}
		secret, err := ReadLine("Base32 secret: ")
		if err != nil {
			return nil, err
		}
		if otpErr := validator.ValidateOTPSecret(secret); otpErr != nil {
			return nil, otpErr
		}
		algoStr, err := ReadLine("Algorithm (SHA1/SHA256/SHA512) [SHA1]: ")
		if err != nil {
			return nil, err
		}
		if algoStr == "" {
			algoStr = "SHA1"
		}
		algoStr = strings.ToUpper(algoStr)
		if algoStr != "SHA1" && algoStr != "SHA256" && algoStr != "SHA512" {
			return nil, fmt.Errorf("unsupported algorithm %q: use SHA1, SHA256, or SHA512", algoStr)
		}
		digitsStr, err := ReadLine("Digits (6 or 8) [6]: ")
		if err != nil {
			return nil, err
		}
		digits := 6
		if digitsStr != "" {
			digits, err = strconv.Atoi(digitsStr)
			if err != nil || (digits != 6 && digits != 8) {
				return nil, fmt.Errorf("digits must be 6 or 8")
			}
		}
		periodStr, err := ReadLine("Period in seconds [30]: ")
		if err != nil {
			return nil, err
		}
		period := uint(30)
		if periodStr != "" {
			n, pErr := strconv.ParseUint(periodStr, 10, 32)
			if pErr != nil || n == 0 {
				return nil, fmt.Errorf("period must be a positive integer")
			}
			period = uint(n)
		}
		payload.OTP = &model.OTPPayload{
			Issuer:    issuer,
			Account:   account,
			Secret:    strings.ToUpper(strings.TrimSpace(secret)),
			Algorithm: algoStr,
			Digits:    digits,
			Period:    period,
		}

	default:
		return nil, fmt.Errorf("unsupported type %q for interactive add", t)
	}
	return payload, nil
}
