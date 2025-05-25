package hd

import (
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa"
	types "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/go-bip39"
)

const mldsa44Type = PubKeyType("mldsa44")

var Mldsa44 = mldsa44Algo{}

type mldsa44Algo struct{}

func (m mldsa44Algo) Name() PubKeyType {
	return mldsa44Type
}

func (m mldsa44Algo) Derive() DeriveFn {
	return func(mnemonic string, bip39Passphrase, hdPath string) ([]byte, error) {
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		masterPriv, ch := ComputeMastersFromSeed(seed)
		if len(hdPath) == 0 {
			return masterPriv[:], nil
		}
		derivedKey, err := DerivePrivateKeyForPath(masterPriv, ch, hdPath)
		if err != nil {
			return nil, err
		}
		return derivedKey, nil
	}
}

func (m mldsa44Algo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		key, err := mldsa.NewPrivKeyFromSecret(bz)
		if err != nil {
			return nil // do not panic, return nil to signal error
		}
		return key
	}
}
