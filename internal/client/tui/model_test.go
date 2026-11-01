package tui

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

func makeTestSecret(id, name string, t model.SecretType) *storage.LocalSecret {
	return &storage.LocalSecret{
		ID:        id,
		Name:      name,
		Type:      t,
		Payload:   []byte("enc"),
		Version:   1,
		UpdatedAt: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
	}
}

func encryptedOTPSecret(t *testing.T) ([]byte, []byte) {
	t.Helper()
	encKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i + 1)
	}
	p := &model.Payload{
		OTP: &model.OTPPayload{
			Issuer:    "GitHub",
			Account:   "alice@example.com",
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
	}
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	aad := crypto.MakeAAD("otp-id", "otp")
	ct, err := crypto.Encrypt(encKey, raw, aad)
	require.NoError(t, err)
	return encKey, ct
}

// --- secretItem ---

func TestSecretItem_Title(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "GitHub", model.SecretTypeCredentials)
	item := secretItem{s: s}
	assert.Equal(t, "GitHub", item.Title())

	s.IsConflict = true
	assert.Equal(t, "GitHub [!]", item.Title())
}

func TestSecretItem_Description(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "GitHub", model.SecretTypeCredentials)
	item := secretItem{s: s}
	desc := item.Description()
	assert.Contains(t, desc, "credentials")
	assert.Contains(t, desc, "2024-01-15")
}

func TestSecretItem_FilterValue(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "My Secret", model.SecretTypeText)
	item := secretItem{s: s}
	assert.Equal(t, "My Secret", item.FilterValue())
}

// --- defaultStyles ---

func TestDefaultStyles(t *testing.T) {
	t.Parallel()

	st := defaultStyles()
	// Styles are non-nil lipgloss styles; just verify they render without panicking.
	_ = st.title.Render("title")
	_ = st.detail.Render("detail")
	_ = st.err.Render("error")
	_ = st.help.Render("help")
	_ = st.spinner.Render(".")
}

// --- New ---

func TestNew(t *testing.T) {
	t.Parallel()

	secrets := []*storage.LocalSecret{
		makeTestSecret("id1", "GitHub", model.SecretTypeCredentials),
		makeTestSecret("id2", "SSH key", model.SecretTypeText),
	}
	encKey := make([]byte, 32)
	m := New(secrets, "alice", encKey)

	assert.Equal(t, secrets, m.secrets)
	assert.Equal(t, "alice", m.login)
	assert.Equal(t, encKey, m.encKey)
	assert.Equal(t, viewList, m.currentView)
}

// --- Init ---

func TestModel_Init(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	cmd := m.Init()
	assert.NotNil(t, cmd)
}

// --- Update: window resize ---

func TestModel_Update_WindowSize(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	mm := updated.(Model)
	assert.Equal(t, 80, mm.width)
	assert.Equal(t, 24, mm.height)
}

// --- Update: spinner tick ---

func TestModel_Update_SpinnerTick(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	tick := spinner.TickMsg{}
	updated, cmd := m.Update(tick)
	assert.NotNil(t, updated)
	_ = cmd
}

// --- Update: decryptedMsg ---

func TestModel_Update_DecryptedMsg(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.decrypting = true
	updated, _ := m.Update(decryptedMsg{content: "hello payload"})
	mm := updated.(Model)
	assert.Equal(t, viewDetail, mm.currentView)
	assert.False(t, mm.decrypting)
}

// --- Update: errMsg ---

func TestModel_Update_ErrMsg(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	updated, _ := m.Update(errMsg{err: assert.AnError})
	mm := updated.(Model)
	assert.Equal(t, viewError, mm.currentView)
	assert.Equal(t, assert.AnError.Error(), mm.errText)
}

// --- updateList ---

func TestModel_UpdateList_Quit(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	_, cmd := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	assert.NotNil(t, cmd)
}

func TestModel_UpdateList_CtrlC(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	_, cmd := m.updateList(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.NotNil(t, cmd)
}

func TestModel_UpdateList_EnterNoSelection(t *testing.T) {
	t.Parallel()

	// Empty list — enter does nothing meaningful.
	m := New(nil, "alice", make([]byte, 32))
	updated, _ := m.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	mm := updated.(Model)
	assert.Equal(t, viewList, mm.currentView)
}

// --- updateDetail ---

func TestModel_UpdateDetail_Esc(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewDetail
	updated, _ := m.updateDetail(tea.KeyMsg{Type: tea.KeyEsc})
	mm := updated.(Model)
	assert.Equal(t, viewList, mm.currentView)
}

func TestModel_UpdateDetail_Q(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewDetail
	updated, cmd := m.updateDetail(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	mm := updated.(Model)
	assert.Equal(t, viewList, mm.currentView)
	_ = cmd
}

func TestModel_UpdateDetail_Backspace(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewDetail
	updated, _ := m.updateDetail(tea.KeyMsg{Type: tea.KeyBackspace})
	mm := updated.(Model)
	assert.Equal(t, viewList, mm.currentView)
}

func TestModel_UpdateDetail_CtrlC(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewDetail
	_, cmd := m.updateDetail(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.NotNil(t, cmd)
}

// --- View ---

func TestModel_View_List(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewList
	v := m.View()
	assert.NotEmpty(t, v)
}

func TestModel_View_Decrypting(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewList
	m.decrypting = true
	v := m.View()
	assert.Contains(t, v, "Decrypting")
}

func TestModel_View_Detail(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "GitHub", model.SecretTypeCredentials)
	m := New([]*storage.LocalSecret{s}, "alice", make([]byte, 32))
	m.currentView = viewDetail
	m.selected = s
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	mm := updated.(Model)
	mm.currentView = viewDetail
	mm.selected = s
	v := mm.View()
	assert.Contains(t, v, "GitHub")
}

func TestModel_View_Error(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewError
	m.errText = "something went wrong"
	v := m.View()
	assert.Contains(t, v, "something went wrong")
}

// --- Update dispatch (detail / error views) ---

func TestModel_Update_KeyInDetailView(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewDetail
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mm := updated.(Model)
	assert.Equal(t, viewList, mm.currentView)
}

func TestModel_Update_KeyInErrorView(t *testing.T) {
	t.Parallel()

	m := New(nil, "alice", make([]byte, 32))
	m.currentView = viewError
	m.errText = "oops"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mm := updated.(Model)
	assert.Equal(t, viewList, mm.currentView)
}

// --- decryptCmd ---

func TestDecryptCmd_Success(t *testing.T) {
	t.Parallel()

	encKey, ct := encryptedOTPSecret(t)
	s := &storage.LocalSecret{
		ID:        "otp-id",
		Type:      model.SecretTypeOTP,
		Name:      "GitHub 2FA",
		Payload:   ct,
		Version:   1,
		UpdatedAt: time.Now(),
	}
	m := New([]*storage.LocalSecret{s}, "alice", encKey)
	fn := m.decryptCmd(s)
	msg := fn()
	dm, ok := msg.(decryptedMsg)
	require.True(t, ok, "expected decryptedMsg, got %T", msg)
	assert.Contains(t, dm.content, "GitHub")
}

func TestDecryptCmd_WrongKey(t *testing.T) {
	t.Parallel()

	_, ct := encryptedOTPSecret(t)
	s := &storage.LocalSecret{
		ID:      "otp-id",
		Type:    model.SecretTypeOTP,
		Name:    "GitHub 2FA",
		Payload: ct,
	}
	wrongKey := make([]byte, 32) // all zeros — won't match
	m := New([]*storage.LocalSecret{s}, "alice", wrongKey)
	fn := m.decryptCmd(s)
	msg := fn()
	_, ok := msg.(errMsg)
	assert.True(t, ok, "expected errMsg, got %T", msg)
}

// --- renderPayload ---

func TestRenderPayload_Credentials(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "GitHub", model.SecretTypeCredentials)
	p := &model.Payload{
		Credentials: &model.CredentialsPayload{
			Login:    "alice",
			Password: "s3cr3t",
			URL:      "https://github.com",
		},
	}
	out := renderPayload(s, p)
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "s3cr3t")
	assert.Contains(t, out, "https://github.com")
}

func TestRenderPayload_Credentials_NoURL(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "GitHub", model.SecretTypeCredentials)
	p := &model.Payload{
		Credentials: &model.CredentialsPayload{Login: "alice", Password: "pw"},
	}
	out := renderPayload(s, p)
	assert.Contains(t, out, "alice")
	assert.NotContains(t, out, "URL")
}

func TestRenderPayload_Text(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "note", model.SecretTypeText)
	p := &model.Payload{Text: &model.TextPayload{Content: "hello world"}}
	out := renderPayload(s, p)
	assert.Contains(t, out, "hello world")
}

func TestRenderPayload_Card(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "Visa", model.SecretTypeCard)
	p := &model.Payload{
		Card: &model.CardPayload{
			Number: "4111111111111111",
			Holder: "Alice",
			Expiry: "12/26",
			CVV:    "123",
		},
	}
	out := renderPayload(s, p)
	assert.Contains(t, out, "4111111111111111")
	assert.Contains(t, out, "Alice")
	assert.Contains(t, out, "123")
}

func TestRenderPayload_OTP(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "GitHub 2FA", model.SecretTypeOTP)
	p := &model.Payload{
		OTP: &model.OTPPayload{
			Issuer:    "GitHub",
			Account:   "alice@example.com",
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
	}
	out := renderPayload(s, p)
	assert.Contains(t, out, "GitHub")
	assert.Contains(t, out, "alice@example.com")
	assert.Contains(t, out, "SHA1")
}

func TestRenderPayload_Binary(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "archive", model.SecretTypeBinary)
	out := renderPayload(s, &model.Payload{})
	assert.Contains(t, out, "download")
}

func TestRenderPayload_WithMeta(t *testing.T) {
	t.Parallel()

	s := makeTestSecret("id1", "note", model.SecretTypeText)
	p := &model.Payload{
		Text: &model.TextPayload{Content: "x"},
		Meta: model.Metadata{
			Pairs: []model.MetaPair{{Key: "env", Value: "prod"}},
			Note:  "important note",
		},
	}
	out := renderPayload(s, p)
	assert.Contains(t, out, "env: prod")
	assert.Contains(t, out, "important note")
}
