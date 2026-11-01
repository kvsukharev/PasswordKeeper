package transport_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/model"
	"github.com/kvsuharev/passwordkeeper/internal/server/transport"
)

func TestProtoTypeRoundtrip(t *testing.T) {
	t.Parallel()

	types := []struct {
		pbType    pb.SecretType
		modelType model.SecretType
	}{
		{pb.SecretType_SECRET_TYPE_CREDENTIALS, model.SecretTypeCredentials},
		{pb.SecretType_SECRET_TYPE_TEXT, model.SecretTypeText},
		{pb.SecretType_SECRET_TYPE_BINARY, model.SecretTypeBinary},
		{pb.SecretType_SECRET_TYPE_CARD, model.SecretTypeCard},
		{pb.SecretType_SECRET_TYPE_OTP, model.SecretTypeOTP},
	}

	for _, tc := range types {
		// proto→model→proto round-trip
		got := transport.ModelTypeToProto(transport.ProtoTypeToModel(tc.pbType))
		assert.Equal(t, tc.pbType, got, "round-trip failed for %v", tc.pbType)
	}
}

func TestProtoTypeToModel_Unspecified(t *testing.T) {
	t.Parallel()
	result := transport.ProtoTypeToModel(pb.SecretType_SECRET_TYPE_UNSPECIFIED)
	assert.Equal(t, model.SecretType(""), result)
}

func TestModelTypeToProto_Unknown(t *testing.T) {
	t.Parallel()
	result := transport.ModelTypeToProto(model.SecretType("unknown"))
	assert.Equal(t, pb.SecretType_SECRET_TYPE_UNSPECIFIED, result)
}
