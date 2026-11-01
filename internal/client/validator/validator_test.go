package validator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kvsuharev/passwordkeeper/internal/client/validator"
)

func TestLuhnCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		number string
		want   bool
	}{
		{"4532015112830366", true},    // valid Visa
		{"79927398713", true},         // classic test vector
		{"79927398710", false},        // bad check digit
		{"4532015112830367", false},   // one off
		{"4111 1111 1111 1111", true}, // spaces OK
		{"4111-1111-1111-1111", true}, // dashes OK
		{"", false},
		{"abc", false},
	}

	for _, tc := range tests {
		got := validator.LuhnCheck(tc.number)
		assert.Equal(t, tc.want, got, "LuhnCheck(%q)", tc.number)
	}
}

func TestValidateExpiry(t *testing.T) {
	t.Parallel()

	assert.NoError(t, validator.ValidateExpiry("12/99"))
	assert.NoError(t, validator.ValidateExpiry("01/99"))
	assert.Error(t, validator.ValidateExpiry("13/99"))
	assert.Error(t, validator.ValidateExpiry("00/99"))
	assert.Error(t, validator.ValidateExpiry("1299"))
	assert.Error(t, validator.ValidateExpiry("01/00")) // expired
}

func TestValidateCVV(t *testing.T) {
	t.Parallel()

	assert.NoError(t, validator.ValidateCVV("123"))
	assert.NoError(t, validator.ValidateCVV("1234"))
	assert.Error(t, validator.ValidateCVV("12"))
	assert.Error(t, validator.ValidateCVV("12345"))
	assert.Error(t, validator.ValidateCVV("12a"))
}

func TestValidateOTPSecret(t *testing.T) {
	t.Parallel()

	// Valid base32 secrets (no padding needed)
	assert.NoError(t, validator.ValidateOTPSecret("JBSWY3DPEHPK3PXP"))
	// Valid with lowercase
	assert.NoError(t, validator.ValidateOTPSecret("jbswy3dpehpk3pxp"))
	// Valid with leading/trailing spaces
	assert.NoError(t, validator.ValidateOTPSecret("  JBSWY3DPEHPK3PXP  "))
	// Valid short secret that needs padding
	assert.NoError(t, validator.ValidateOTPSecret("MFRA"))
	// Invalid: not base32
	assert.Error(t, validator.ValidateOTPSecret("not-valid-base32!!!"))
	// Invalid: contains 9 (not in base32 alphabet)
	assert.Error(t, validator.ValidateOTPSecret("99999999"))
}
