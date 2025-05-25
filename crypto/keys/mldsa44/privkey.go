package mldsa44

import (
	"encoding/base64"
	"errors"
	io "io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// customProtobufType defines the methods required for protobuf serialization.
type customProtobufType interface {
	Marshal() ([]byte, error)
	MarshalTo([]byte) (int, error)
	MarshalJSON() ([]byte, error)
	Size() int
	Unmarshal([]byte) error
	UnmarshalJSON([]byte) error
}

var _ customProtobufType = (*mldsa44SK)(nil)

type mldsa44SK struct {
	mldsa44.PrivateKey
}

// GenPrivKey generates a new mldsa44 private key. It uses operating system randomness.
func GenPrivKey() (*PrivKeyMLDSA44, error) {
	_, privKey, err := mldsa44.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &PrivKeyMLDSA44{Key: privKey.Bytes()}, nil
}

// PrivKeyMLDSA44 struct with Key []byte field (protobuf tag matches proto definition).
type PrivKeyMLDSA44 struct {
	Key []byte `protobuf:"bytes,1,opt,name=secret,proto3" json:"secret,omitempty"`
}

// Ensure PrivKeyMLDSA44 implements cryptotypes.PrivKey (which extends proto.Message).
var _ cryptotypes.PrivKey = (*PrivKeyMLDSA44)(nil)

// ProtoMessage implements proto.Message for PrivKeyMLDSA44.
func (m *PrivKeyMLDSA44) ProtoMessage() {}

// Reset implements proto.Message for PrivKeyMLDSA44.
func (m *PrivKeyMLDSA44) Reset() { *m = PrivKeyMLDSA44{} }

// String implements proto.Message for PrivKeyMLDSA44.
func (m *PrivKeyMLDSA44) String() string {
	return base64.StdEncoding.EncodeToString(m.Key)
}

// PubKey implements SDK PrivKey interface.
func (m *PrivKeyMLDSA44) PubKey() cryptotypes.PubKey {
	privKey := new(mldsa44.PrivateKey)
	if m == nil || m.Key == nil {
		return nil
	}
	if err := privKey.UnmarshalBinary(m.Key); err != nil {
		return nil
	}
	pub := privKey.Public()
	pubKey, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return nil
	}
	return &PubKey{Key: pubKey.Bytes()}
}

// Type returns key type name. Implements SDK PrivKey interface.
func (m *PrivKeyMLDSA44) Type() string {
	return "tendermint/PrivKeyMLDSA44"
}

// Sign hashes and signs the message using mldsa44. Implements sdk.PrivKey interface.
func (m *PrivKeyMLDSA44) Sign(msg []byte) ([]byte, error) {
	privKey := new(mldsa44.PrivateKey)
	if m == nil || m.Key == nil {
		return nil, nil
	}
	if err := privKey.UnmarshalBinary(m.Key); err != nil {
		return nil, err
	}
	return privKey.Scheme().Sign(privKey, msg, nil), nil
}

// Bytes serialize the private key.
func (m *PrivKeyMLDSA44) Bytes() []byte {
	if m == nil {
		return nil
	}
	return m.Key
}

// Equals implements SDK PrivKey interface.
func (m *PrivKeyMLDSA44) Equals(other cryptotypes.LedgerPrivKey) bool {
	sk2, ok := other.(*PrivKeyMLDSA44)
	if !ok {
		return false
	}
	return string(m.Bytes()) == string(sk2.Bytes())
}

// Marshal implements customProtobufType.
func (sk mldsa44SK) Marshal() ([]byte, error) {
	return sk.Bytes(), nil
}

// MarshalTo implements customProtobufType.
func (sk *mldsa44SK) MarshalTo(data []byte) (int, error) {
	bz := sk.Bytes()
	if len(data) < len(bz) {
		return 0, io.ErrShortBuffer
	}
	copy(data, bz)
	return len(bz), nil
}

// MarshalJSON implements customProtobufType.
func (sk mldsa44SK) MarshalJSON() ([]byte, error) {
	b64 := base64.StdEncoding.EncodeToString(sk.Bytes())
	return []byte("\"" + b64 + "\""), nil
}

// Size implements customProtobufType.
func (sk *mldsa44SK) Size() int {
	if sk == nil {
		return 0
	}
	return len(sk.Bytes())
}

// UnmarshalJSON implements customProtobufType.
func (sk *mldsa44SK) UnmarshalJSON(data []byte) error {
	bz, err := base64.StdEncoding.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	return sk.PrivateKey.UnmarshalBinary(bz)
}

// Unmarshal implements proto.Marshaler interface
func (sk *mldsa44SK) Unmarshal(bz []byte) error {
	return sk.PrivateKey.UnmarshalBinary(bz)
}

// NewPrivKeyFromSecret creates a mldsa44 private key from a secret seed (must be 32 bytes).
func NewPrivKeyFromSecret(secret []byte) (*PrivKeyMLDSA44, error) {
	if len(secret) != mldsa44.SeedSize {
		return nil, errors.New("secret must be 32 bytes for mldsa44")
	}
	var seed [mldsa44.SeedSize]byte
	copy(seed[:], secret)
	privKey, _ := mldsa44.NewKeyFromSeed(&seed)
	return &PrivKeyMLDSA44{Key: privKey.Bytes()}, nil
}
