package commands

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/model"
)

// --- parseSecretType ---

func TestParseSecretType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input     string
		wantPb    pb.SecretType
		wantModel model.SecretType
		wantErr   bool
	}{
		{"credentials", pb.SecretType_SECRET_TYPE_CREDENTIALS, model.SecretTypeCredentials, false},
		{"creds", pb.SecretType_SECRET_TYPE_CREDENTIALS, model.SecretTypeCredentials, false},
		{"text", pb.SecretType_SECRET_TYPE_TEXT, model.SecretTypeText, false},
		{"card", pb.SecretType_SECRET_TYPE_CARD, model.SecretTypeCard, false},
		{"unknown", 0, "", true},
		{"binary", 0, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			gotPb, gotModel, err := parseSecretType(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantPb, gotPb)
			assert.Equal(t, tc.wantModel, gotModel)
		})
	}
}

// --- parseMeta ---

func TestParseMeta(t *testing.T) {
	t.Parallel()

	t.Run("empty inputs", func(t *testing.T) {
		m := parseMeta(nil, "")
		assert.Empty(t, m.Pairs)
		assert.Empty(t, m.Note)
	})

	t.Run("key:value pairs parsed", func(t *testing.T) {
		m := parseMeta([]string{"url:https://example.com", "env:prod"}, "some note")
		require.Len(t, m.Pairs, 2)
		assert.Equal(t, "url", m.Pairs[0].Key)
		assert.Equal(t, "https://example.com", m.Pairs[0].Value)
		assert.Equal(t, "env", m.Pairs[1].Key)
		assert.Equal(t, "prod", m.Pairs[1].Value)
		assert.Equal(t, "some note", m.Note)
	})

	t.Run("entry without colon is skipped", func(t *testing.T) {
		m := parseMeta([]string{"nocolon"}, "")
		assert.Empty(t, m.Pairs)
	})

	t.Run("value with colon in it is preserved", func(t *testing.T) {
		m := parseMeta([]string{"url:https://host:8080/path"}, "")
		require.Len(t, m.Pairs, 1)
		assert.Equal(t, "url", m.Pairs[0].Key)
		assert.Equal(t, "https://host:8080/path", m.Pairs[0].Value)
	})
}

// --- ZeroBytes ---

func TestZeroBytes(t *testing.T) {
	t.Parallel()

	b := []byte("secret-password")
	ZeroBytes(b)
	for _, v := range b {
		assert.Equal(t, byte(0), v)
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	t.Parallel()
	ZeroBytes(nil)
	ZeroBytes([]byte{})
}

// --- type converters ---

func TestPbSecretTypeToModel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in  pb.SecretType
		out model.SecretType
	}{
		{pb.SecretType_SECRET_TYPE_CREDENTIALS, model.SecretTypeCredentials},
		{pb.SecretType_SECRET_TYPE_TEXT, model.SecretTypeText},
		{pb.SecretType_SECRET_TYPE_BINARY, model.SecretTypeBinary},
		{pb.SecretType_SECRET_TYPE_CARD, model.SecretTypeCard},
		{pb.SecretType_SECRET_TYPE_OTP, model.SecretTypeOTP},
		{pb.SecretType_SECRET_TYPE_UNSPECIFIED, model.SecretType("")},
	}
	for _, c := range cases {
		assert.Equal(t, c.out, pbSecretTypeToModel(c.in))
	}
}

func TestModelSecretTypeToPb(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in  model.SecretType
		out pb.SecretType
	}{
		{model.SecretTypeCredentials, pb.SecretType_SECRET_TYPE_CREDENTIALS},
		{model.SecretTypeText, pb.SecretType_SECRET_TYPE_TEXT},
		{model.SecretTypeBinary, pb.SecretType_SECRET_TYPE_BINARY},
		{model.SecretTypeCard, pb.SecretType_SECRET_TYPE_CARD},
		{model.SecretTypeOTP, pb.SecretType_SECRET_TYPE_OTP},
		{model.SecretType("unknown"), pb.SecretType_SECRET_TYPE_UNSPECIFIED},
	}
	for _, c := range cases {
		assert.Equal(t, c.out, modelSecretTypeToPb(c.in))
	}
}

func TestPendingActionToPb(t *testing.T) {
	t.Parallel()

	assert.Equal(t, pb.ChangeAction_CHANGE_ACTION_CREATE, pendingActionToPb("create"))
	assert.Equal(t, pb.ChangeAction_CHANGE_ACTION_UPDATE, pendingActionToPb("update"))
	assert.Equal(t, pb.ChangeAction_CHANGE_ACTION_DELETE, pendingActionToPb("delete"))
	assert.Equal(t, pb.ChangeAction_CHANGE_ACTION_UNSPECIFIED, pendingActionToPb("unknown"))
}

// --- isOfflineError ---

func TestIsOfflineError(t *testing.T) {
	t.Parallel()

	assert.True(t, isOfflineError(status.Error(codes.Unavailable, "no route")))
	assert.True(t, isOfflineError(status.Error(codes.DeadlineExceeded, "timeout")))
	assert.False(t, isOfflineError(status.Error(codes.Internal, "oops")))
	assert.False(t, isOfflineError(status.Error(codes.NotFound, "gone")))
	assert.False(t, isOfflineError(nil))
	assert.False(t, isOfflineError(assert.AnError))
}

// --- localSecretFromPb ---

func TestLocalSecretFromPb(t *testing.T) {
	t.Parallel()

	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	s := &pb.Secret{
		Meta: &pb.SecretMeta{
			Id:        "sec-1",
			Type:      pb.SecretType_SECRET_TYPE_TEXT,
			Name:      "my note",
			Version:   7,
			Deleted:   false,
			UpdatedAt: timestamppb.New(ts),
		},
		Payload: []byte("encrypted"),
	}

	ls := localSecretFromPb(s)
	assert.Equal(t, "sec-1", ls.ID)
	assert.Equal(t, model.SecretTypeText, ls.Type)
	assert.Equal(t, "my note", ls.Name)
	assert.Equal(t, []byte("encrypted"), ls.Payload)
	assert.Equal(t, int64(7), ls.Version)
	assert.False(t, ls.Deleted)
	assert.Equal(t, ts.Unix(), ls.UpdatedAt.Unix())
}

func TestLocalSecretFromPb_NilUpdatedAt(t *testing.T) {
	t.Parallel()

	s := &pb.Secret{
		Meta:    &pb.SecretMeta{Id: "x", Name: "y"},
		Payload: []byte("enc"),
	}
	ls := localSecretFromPb(s)
	assert.Equal(t, "x", ls.ID)
	assert.True(t, ls.UpdatedAt.IsZero())
}

// --- joinQuoted ---

func TestJoinQuoted(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `"alice", "bob"`, joinQuoted([]string{"alice", "bob"}))
	assert.Equal(t, `"one"`, joinQuoted([]string{"one"}))
	assert.Equal(t, "", joinQuoted(nil))
}

// --- printPayload ---

func TestPrintPayload_Credentials(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &model.Payload{
		Credentials: &model.CredentialsPayload{Login: "user", Password: "pw", URL: "https://example.com"},
	}
	printPayload(&buf, "my-secret", model.SecretTypeCredentials, 3, p, true)
	out := buf.String()
	assert.Contains(t, out, "user")
	assert.Contains(t, out, "pw")
	assert.Contains(t, out, "https://example.com")
	assert.Contains(t, out, "Version: 3")
}

func TestPrintPayload_CredentialsMasked(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &model.Payload{
		Credentials: &model.CredentialsPayload{Login: "user", Password: "secret"},
	}
	printPayload(&buf, "s", model.SecretTypeCredentials, 1, p, false)
	out := buf.String()
	assert.NotContains(t, out, "secret")
	assert.Contains(t, out, "***")
}

func TestPrintPayload_Text(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &model.Payload{Text: &model.TextPayload{Content: "hello world"}}
	printPayload(&buf, "note", model.SecretTypeText, 1, p, false)
	assert.Contains(t, buf.String(), "hello world")
}

func TestPrintPayload_Card(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &model.Payload{
		Card: &model.CardPayload{Number: "4111111111111111", Holder: "Alice", Expiry: "12/26", CVV: "123"},
	}
	printPayload(&buf, "card", model.SecretTypeCard, 1, p, true)
	out := buf.String()
	assert.Contains(t, out, "4111111111111111")
	assert.Contains(t, out, "123")
}

func TestPrintPayload_Binary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	printPayload(&buf, "file", model.SecretTypeBinary, 1, &model.Payload{}, false)
	assert.Contains(t, buf.String(), "encrypted binary")
}

func TestPrintPayload_WithMeta(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &model.Payload{
		Text: &model.TextPayload{Content: "x"},
		Meta: model.Metadata{
			Pairs: []model.MetaPair{{Key: "env", Value: "prod"}},
			Note:  "important",
		},
	}
	printPayload(&buf, "note", model.SecretTypeText, 1, p, false)
	out := buf.String()
	assert.Contains(t, out, "env: prod")
	assert.Contains(t, out, "Note: important")
}
