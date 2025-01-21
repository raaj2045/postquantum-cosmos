package dillithium

import (
	"bytes"

	"github.com/cloudflare/circl/sign/eddilithium2"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// GenPrivKey generates a new dilithium mode2 private key. It uses operating system randomness.
func GenPrivKey() (*PrivKey, error) {
	_, prkey, err := eddilithium2.GenerateKey(nil)
	return &PrivKey{Secret: prkey.Bytes()}, err
}

// PubKey implements SDK PrivKey interface.
func (m *PrivKey) PubKey() cryptotypes.PubKey {
	privKey := new(eddilithium2.PrivateKey)

	if err := privKey.UnmarshalBinary(m.Secret); err != nil {
		panic(err)
	}

	pubKey := privKey.Public()

	edPubKey, ok := pubKey.(*eddilithium2.PublicKey)
	if !ok {
		panic("expected eddilithium2.PublicKey")
	}

	return &PubKey{Key: edPubKey.Bytes()}
}

// // String implements SDK proto.Message interface.
// func (m *PrivKey) String() string {
// 	return fmt.Sprintf("PrivKey(ed25519dilithium2-%X)", m.Secret)
// }

// Type returns key type name. Implements SDK PrivKey interface.
func (m *PrivKey) Type() string {
	return "PrivKey(ed25519dilithium2)"
}

// Sign hashes and signs the message usign Dillithium2. Implements sdk.PrivKey interface.
func (m *PrivKey) Sign(msg []byte) ([]byte, error) {
	privKey := new(eddilithium2.PrivateKey)

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

// type dilithium2SK struct {
// 	eddilithium2.PrivateKey
// }

// Size implements proto.Marshaler interface
// func (sk *PrivKey) Size() int {
// 	if sk == nil {
// 		return 0
// 	}
// 	return sk.Secret.Scheme().PrivateKeySize()
// }

// // Unmarshal implements proto.Marshaler interface
// func (sk *PrivKey) Unmarshal(bz []byte) error {
// 	return sk.Secret.UnmarshalBinary(bz)
// }
