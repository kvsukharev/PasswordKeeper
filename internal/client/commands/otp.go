package commands

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"

	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// newOtpCmd returns the cobra command for generating OTP codes.
func newOtpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "otp <name>",
		Short: "Generate the current TOTP code for an OTP secret",
		Args:  cobra.ExactArgs(1),
		RunE:  runOtp,
	}
}

func runOtp(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("secret %q not found in local cache", args[0])
	}

	if sec.Type != model.SecretTypeOTP {
		return fmt.Errorf("secret %q is not of type otp (got %s)", args[0], sec.Type)
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
	if unmarshalErr := json.Unmarshal(plaintext, &payload); unmarshalErr != nil {
		return fmt.Errorf("parse payload: %w", unmarshalErr)
	}
	if payload.OTP == nil {
		return fmt.Errorf("secret %q has no OTP data", args[0])
	}

	o := payload.OTP
	now := time.Now()
	opts := totp.ValidateOpts{
		Period:    o.Period,
		Digits:    otpDigits(o.Digits),
		Algorithm: otpAlgorithm(o.Algorithm),
	}

	code, err := totp.GenerateCodeCustom(o.Secret, now, opts)
	if err != nil {
		return fmt.Errorf("generate TOTP code: %w", err)
	}

	remaining := int(opts.Period) - int(now.Unix())%int(opts.Period)
	fmt.Fprintf(cmd.OutOrStdout(), "%s  (%ds remaining)\n", code, remaining)
	return nil
}

// otpDigits converts an integer digit count to otp.Digits.
func otpDigits(n int) otp.Digits {
	if n == 8 {
		return otp.DigitsEight
	}
	return otp.DigitsSix
}

// otpAlgorithm converts the algorithm name string to otp.Algorithm.
func otpAlgorithm(name string) otp.Algorithm {
	switch name {
	case "SHA256":
		return otp.AlgorithmSHA256
	case "SHA512":
		return otp.AlgorithmSHA512
	default:
		return otp.AlgorithmSHA1
	}
}
