package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kvsuharev/passwordkeeper/internal/client/crypto"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// view enumerates the TUI screens.
type view int

const (
	viewList   view = iota // main list of secrets
	viewDetail             // decrypted detail of one secret
	viewError              // error message overlay
)

// secretItem wraps a LocalSecret for the bubbles list component.
type secretItem struct {
	s *storage.LocalSecret
}

func (i secretItem) Title() string {
	if i.s.IsConflict {
		return i.s.Name + " [!]"
	}
	return i.s.Name
}
func (i secretItem) Description() string {
	return fmt.Sprintf("%s  v%d  %s", i.s.Type, i.s.Version, i.s.UpdatedAt.Format("2006-01-02"))
}
func (i secretItem) FilterValue() string { return i.s.Name }

// decryptedMsg carries the decrypted detail string back to the model.
type decryptedMsg struct {
	content string
}

// errMsg carries an error back to the model.
type errMsg struct{ err error }

// styles holds all lipgloss renderers.
type styles struct {
	title   lipgloss.Style
	detail  lipgloss.Style
	err     lipgloss.Style
	help    lipgloss.Style
	spinner lipgloss.Style
}

func defaultStyles() styles {
	return styles{
		title:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")),
		detail:  lipgloss.NewStyle().Padding(1, 2),
		err:     lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true),
		help:    lipgloss.NewStyle().Foreground(lipgloss.Color("241")),
		spinner: lipgloss.NewStyle().Foreground(lipgloss.Color("62")),
	}
}

// Model is the root Bubble Tea model for the PasswordKeeper TUI.
type Model struct {
	list     list.Model
	viewport viewport.Model
	spinner  spinner.Model
	styles   styles

	secrets  []*storage.LocalSecret
	login    string
	encKey   []byte
	selected *storage.LocalSecret

	currentView view
	decrypting  bool
	errText     string

	width  int
	height int
}

// New creates a TUI Model pre-loaded with secrets and the derived enc key.
// encKey is held in memory only and zeroed when the program quits.
func New(secrets []*storage.LocalSecret, login string, encKey []byte) Model {
	items := make([]list.Item, len(secrets))
	for i, s := range secrets {
		items[i] = secretItem{s: s}
	}

	delegate := list.NewDefaultDelegate()
	l := list.New(items, delegate, 0, 0)
	l.Title = "PasswordKeeper"
	l.SetShowHelp(true)
	l.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "view")),
			key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
		}
	}

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	st := defaultStyles()
	sp.Style = st.spinner

	return Model{
		list:    l,
		spinner: sp,
		styles:  st,
		secrets: secrets,
		login:   login,
		encKey:  encKey,
	}
}

// Init starts the spinner tick.
func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update processes incoming messages and keyboard events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height)
		m.viewport = viewport.New(msg.Width, msg.Height-4)
		return m, nil

	case tea.KeyMsg:
		switch m.currentView {
		case viewList:
			return m.updateList(msg)
		case viewDetail, viewError:
			return m.updateDetail(msg)
		}

	case decryptedMsg:
		m.decrypting = false
		m.viewport.SetContent(msg.content)
		m.currentView = viewDetail
		return m, nil

	case errMsg:
		m.decrypting = false
		m.errText = msg.err.Error()
		m.currentView = viewError
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m Model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		crypto.ZeroBytes(m.encKey) //nolint:staticcheck // intentional in-place zero
		return m, tea.Quit
	case "enter":
		if i, ok := m.list.SelectedItem().(secretItem); ok {
			m.selected = i.s
			m.decrypting = true
			return m, m.decryptCmd(i.s)
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m Model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace":
		m.currentView = viewList
		return m, nil
	case "ctrl+c":
		crypto.ZeroBytes(m.encKey) //nolint:staticcheck // intentional in-place zero
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

// decryptCmd returns a tea.Cmd that decrypts the selected secret off the main
// goroutine to avoid blocking the event loop.
func (m Model) decryptCmd(s *storage.LocalSecret) tea.Cmd {
	return func() tea.Msg {
		aad := crypto.MakeAAD(s.ID, string(s.Type))
		plaintext, err := crypto.Decrypt(m.encKey, s.Payload, aad)
		if err != nil {
			return errMsg{fmt.Errorf("decrypt failed (wrong master password?): %w", err)}
		}
		var payload model.Payload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return errMsg{fmt.Errorf("parse payload: %w", err)}
		}
		return decryptedMsg{content: renderPayload(s, &payload)}
	}
}

// View renders the current screen.
func (m Model) View() string {
	switch m.currentView {
	case viewDetail:
		header := m.styles.title.Render(m.selected.Name)
		help := m.styles.help.Render("↑/↓ scroll  esc back  q quit")
		return header + "\n" + m.styles.detail.Render(m.viewport.View()) + "\n" + help
	case viewError:
		msg := m.styles.err.Render("Error: " + m.errText)
		help := m.styles.help.Render("\nPress any key to go back.")
		return msg + help
	case viewList:
		// fall through to list view below
	}
	if m.decrypting {
		return m.spinner.View() + " Decrypting…"
	}
	return m.list.View()
}

// renderPayload formats a decrypted payload as plain text for the viewport.
func renderPayload(s *storage.LocalSecret, p *model.Payload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Type:    %s\n", string(s.Type))
	fmt.Fprintf(&b, "Version: %d\n", s.Version)
	fmt.Fprintf(&b, "Updated: %s\n\n", s.UpdatedAt.Format(time.RFC3339))

	switch s.Type {
	case model.SecretTypeCredentials:
		if p.Credentials != nil {
			fmt.Fprintf(&b, "Login:    %s\n", p.Credentials.Login)
			fmt.Fprintf(&b, "Password: %s\n", p.Credentials.Password)
			if p.Credentials.URL != "" {
				fmt.Fprintf(&b, "URL:      %s\n", p.Credentials.URL)
			}
		}
	case model.SecretTypeText:
		if p.Text != nil {
			fmt.Fprintf(&b, "%s\n", p.Text.Content)
		}
	case model.SecretTypeCard:
		if p.Card != nil {
			fmt.Fprintf(&b, "Number: %s\n", p.Card.Number)
			fmt.Fprintf(&b, "Holder: %s\n", p.Card.Holder)
			fmt.Fprintf(&b, "Expiry: %s\n", p.Card.Expiry)
			fmt.Fprintf(&b, "CVV:    %s\n", p.Card.CVV)
		}
	case model.SecretTypeOTP:
		if p.OTP != nil {
			fmt.Fprintf(&b, "Issuer:  %s\n", p.OTP.Issuer)
			fmt.Fprintf(&b, "Account: %s\n", p.OTP.Account)
			fmt.Fprintf(&b, "Secret:  %s\n", p.OTP.Secret)
			fmt.Fprintf(&b, "Algo:    %s  Digits: %d  Period: %ds\n",
				p.OTP.Algorithm, p.OTP.Digits, p.OTP.Period)
		}
	default:
		fmt.Fprintln(&b, "(binary — use 'download' command to export)")
	}

	if len(p.Meta.Pairs) > 0 || p.Meta.Note != "" {
		fmt.Fprintln(&b)
		for _, kv := range p.Meta.Pairs {
			fmt.Fprintf(&b, "%s: %s\n", kv.Key, kv.Value)
		}
		if p.Meta.Note != "" {
			fmt.Fprintf(&b, "Note: %s\n", p.Meta.Note)
		}
	}
	return b.String()
}
