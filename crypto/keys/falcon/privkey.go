package falcon

import (
	"bytes"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// GenPrivKey generates a new mldsa 44 private key. It uses operating system randomness.
func GenPrivKey() (*PrivKey, error) {
	_, prkey, err := mldsa44.GenerateKey(nil)
	return &PrivKey{Secret: prkey.Bytes()}, err
}

// PubKey implements SDK PrivKey interface.
func (m *PrivKey) PubKey() cryptotypes.PubKey {
	privKey := new(mldsa44.PrivateKey)

	if err := privKey.UnmarshalBinary(m.Secret); err != nil {
		panic(err)
	}

	pubKey := privKey.Public()

	edPubKey, ok := pubKey.(*mldsa44.PublicKey)
	if !ok {
		panic("expected mldsa44.PublicKey")
	}

	return &PubKey{Key: edPubKey.Bytes()}
}

// Type returns key type name. Implements SDK PrivKey interface.
func (m *PrivKey) Type() string {
	return "PrivKey(ed25519dilithium2)"
}

// Sign hashes and signs the message usign Dillithium2. Implements sdk.PrivKey interface.
func (m *PrivKey) Sign(msg []byte) ([]byte, error) {
	privKey := new(mldsa44.PrivateKey)

	if err := privKey.UnmarshalBinary(m.Secret); err != nil {
		panic(err)
	}

	return privKey.Scheme().Sign(privKey, msg, nil), nil
}

// Bytes serialize the private key.
func (m *PrivKey) Bytes() []byte {
	if m == nil {
		return nil
	}
	return m.Secret
}

// Equals implements SDK PrivKey interface.
func (m *PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	if other == nil {
		return false
	}
	otherKey, ok := other.(*PrivKey)
	if !ok {
		return false
	}
	// Compare the underlying secret bytes
	return bytes.Equal(m.Secret, otherKey.Secret)
}
