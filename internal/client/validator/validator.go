package validator

import (
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LuhnCheck returns true if number passes the Luhn algorithm.
// Spaces and dashes are stripped before validation.
func LuhnCheck(number string) bool {
	digits := strings.ReplaceAll(strings.ReplaceAll(number, " ", ""), "-", "")
	if len(digits) < 2 {
		return false
	}
	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}
	return sum%10 == 0
}

// ValidateExpiry checks that mmyy is a valid MM/YY expiry date that has not passed.
func ValidateExpiry(mmyy string) error {
	if len(mmyy) != 5 || mmyy[2] != '/' {
		return fmt.Errorf("expiry must be MM/YY format, got %q", mmyy)
	}
	month, err1 := strconv.Atoi(mmyy[:2])
	year, err2 := strconv.Atoi(mmyy[3:])
	if err1 != nil || err2 != nil || month < 1 || month > 12 {
		return fmt.Errorf("invalid expiry date %q", mmyy)
	}
	fullYear := 2000 + year
	now := time.Now()
	if fullYear < now.Year() || (fullYear == now.Year() && month < int(now.Month())) {
		return fmt.Errorf("card expired %s", mmyy)
	}
	return nil
}

// ValidateCVV checks that cvv is 3 or 4 decimal digits.
func ValidateCVV(cvv string) error {
	if len(cvv) < 3 || len(cvv) > 4 {
		return fmt.Errorf("CVV must be 3 or 4 digits")
	}
	for _, c := range cvv {
		if c < '0' || c > '9' {
			return fmt.Errorf("CVV must contain only digits")
		}
	}
	return nil
}

// ValidateOTPSecret checks that secret is a valid base32-encoded TOTP seed.
// Padding is optional; the check is case-insensitive.
func ValidateOTPSecret(secret string) error {
	upper := strings.ToUpper(strings.TrimSpace(secret))
	// Add padding if necessary.
	if rem := len(upper) % 8; rem != 0 {
		upper += strings.Repeat("=", 8-rem)
	}
	if _, err := base32.StdEncoding.DecodeString(upper); err != nil {
		return fmt.Errorf("OTP secret must be a valid base32 string: %w", err)
	}
	return nil
}
