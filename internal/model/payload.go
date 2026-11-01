package model

// Payload is the client-side plaintext representation of a secret's content.
// It is JSON-encoded and AES-256-GCM encrypted before storage; the server
// never sees the plaintext.
type Payload struct {
	Credentials *CredentialsPayload `json:"credentials,omitempty"`
	Text        *TextPayload        `json:"text,omitempty"`
	Card        *CardPayload        `json:"card,omitempty"`
	OTP         *OTPPayload         `json:"otp,omitempty"`
	Meta        Metadata            `json:"meta"`
}

// CredentialsPayload holds a login/password pair with an optional URL.
type CredentialsPayload struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
}

// TextPayload holds arbitrary plaintext content.
type TextPayload struct {
	Content string `json:"content"`
}

// CardPayload holds bank card details.
type CardPayload struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"` // MM/YY
	CVV    string `json:"cvv"`
}

// OTPPayload holds a TOTP/HOTP one-time-password configuration.
// The Secret field is a base32-encoded seed; it is encrypted together with
// all other payload fields and never leaves the client in plaintext.
type OTPPayload struct {
	// Issuer is the organisation that issued the OTP credential (e.g. "GitHub").
	Issuer string `json:"issuer"`
	// Account is the account identifier (e.g. "alice@example.com").
	Account string `json:"account"`
	// Secret is the base32-encoded TOTP/HOTP seed.
	Secret string `json:"secret"`
	// Algorithm is the HMAC hash algorithm: SHA1, SHA256 or SHA512.
	Algorithm string `json:"algorithm"`
	// Digits is the number of digits in each OTP code (6 or 8).
	Digits int `json:"digits"`
	// Period is the TOTP step in seconds (default 30).
	Period uint `json:"period"`
}

// Metadata is an optional bag of key-value pairs and a free-text note attached
// to any secret type.
type Metadata struct {
	Pairs []MetaPair `json:"pairs,omitempty"`
	Note  string     `json:"note,omitempty"`
}

// MetaPair is a single key/value entry in Metadata.
type MetaPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
