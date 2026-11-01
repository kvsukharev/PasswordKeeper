package model

// Payload is the client-side plaintext representation of a secret's content.
// It is JSON-encoded and AES-256-GCM encrypted before storage; the server
// never sees the plaintext.
type Payload struct {
	Credentials *CredentialsPayload `json:"credentials,omitempty"`
	Text        *TextPayload        `json:"text,omitempty"`
	Card        *CardPayload        `json:"card,omitempty"`
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
