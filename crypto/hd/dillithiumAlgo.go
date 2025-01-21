package hd

import (
	"github.com/cosmos/cosmos-sdk/crypto/keys/dillithium" // You'll need to implement this
	"github.com/cosmos/cosmos-sdk/crypto/types"
	bip39 "github.com/cosmos/go-bip39"
)

// Key types
const (
	DilithiumType = PubKeyType("dillithium")
)

var (
	// Dillithium2 uses mode2 Dillithium PQC parameters
	Dillithium2 = DilithiumAlgo{}
)

// DilithiumAlgo implements the dillithium signing algorithm
type DilithiumAlgo struct{}

func (d DilithiumAlgo) Name() PubKeyType {
	return DilithiumType
}

func (d DilithiumAlgo) Derive() DeriveFn {
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

func (d DilithiumAlgo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		key, err := dillithium.GenPrivKey()
		if err != nil {
			panic(err)
		}
		return key
	}
}
