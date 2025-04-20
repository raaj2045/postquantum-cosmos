package falcon

import (
	"bytes"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	tmcrypto "github.com/tendermint/tendermint/crypto"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// Bytes implements SDK PubKey interface.
func (m *PubKey) Bytes() []byte {
	if m == nil {
		return nil
	}
	return m.Key
}

// Equals implements SDK PubKey interface.
func (m *PubKey) Equals(other cryptotypes.PubKey) bool {
	if other == nil {
		return false
	}
	otherKey, ok := other.(*PubKey)
	if !ok {
		return false
	}
	// Compare the underlying bytes
	return bytes.Equal(m.Key, otherKey.Key)
}

// Address implements SDK PubKey interface.
func (m *PubKey) Address() tmcrypto.Address {
	if m == nil {
		return nil
	}
	return tmcrypto.AddressHash(m.Bytes())
}

// Type returns key type name. Implements SDK PubKey interface.
func (m *PubKey) Type() string {
	return "PubKey(ed25519dilithium2)"
}

// VerifySignature implements SDK PubKey interface.
func (m *PubKey) VerifySignature(msg []byte, sig []byte) bool {
	pubKey := new(mldsa44.PublicKey)

	if err := pubKey.UnmarshalBinary(m.Key); err != nil {
		panic(err)
	}

	return pubKey.Scheme().Verify(pubKey, msg, sig, nil)
}
