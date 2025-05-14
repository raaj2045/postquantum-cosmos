package hd

import (
	"bytes"

	circlMLDSA "github.com/cloudflare/circl/sign/mldsa/mldsa44" // Alias circl library
	sdkMLDSA "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa44" // Alias SDK library
	"github.com/cosmos/cosmos-sdk/crypto/types"
	bip39 "github.com/cosmos/go-bip39"
)

// Key types
const (
	Mldsa44Type = PubKeyType("mldsa44")
)

var (
	// mldsa44 PQC parameters
	Mldsa44 = Mldsa44Algo{}
)

// Mldsa44Algo implements the mldsa44 signing algorithm
type Mldsa44Algo struct{}

func (d Mldsa44Algo) Name() PubKeyType {
	return Mldsa44Type
}

func (d Mldsa44Algo) Derive() DeriveFn {
	return func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		masterPriv, ch := ComputeMastersFromSeed(seed)
		if len(hdPath) == 0 {
			return masterPriv[:], nil
		}

		return DerivePrivateKeyForPath(masterPriv, ch, hdPath)
	}
}

func (d Mldsa44Algo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		// Use the derived bytes (bz) as the seed for deterministic generation
		// Use the aliased circlMLDSA for GenerateKey
		_, privKey, err := circlMLDSA.GenerateKey(bytes.NewReader(bz))
		if err != nil {
			// Handle error appropriately - panic is generally discouraged in libraries
			// For now, we'll keep the panic to match original, but this could be improved.
			panic(err)
		}
		// Return the SDK's PrivKey type, using the aliased sdkMLDSA
		return &sdkMLDSA.PrivKey{Secret: privKey.Bytes()}
	}
}
