package main

import (
	"fmt"
	"log"

	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa"
)

func main() {
	fmt.Println("🧪 Testing MLDSA44 Implementation")

	// Test 1: Basic key generation and signing
	log.Println("Creating private key...")
	privKey, err := mldsa.GenPrivKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	log.Println("Getting public key...")
	pubKey := privKey.PubKey()
	if pubKey == nil {
		log.Fatal("Public key is nil")
	}

	// Test 2: Sign and verify
	message := []byte("Hello, MLDSA44!")
	log.Printf("Signing message: %s", string(message))

	signature, err := privKey.Sign(message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	log.Printf("Signature created, length: %d", len(signature))

	// Test 3: Verify signature
	log.Println("Verifying signature...")
	isValid := pubKey.VerifySignature(message, signature)

	if isValid {
		fmt.Println("✅ SUCCESS: Signature verification passed!")
	} else {
		fmt.Println("❌ FAILURE: Signature verification failed!")
		log.Fatal("Basic signature verification failed")
	}

	// Test 4: Test with wrong message
	log.Println("Testing with wrong message...")
	wrongMessage := []byte("Wrong message")
	isValidWrong := pubKey.VerifySignature(wrongMessage, signature)

	if !isValidWrong {
		fmt.Println("✅ SUCCESS: Correctly rejected wrong message!")
	} else {
		fmt.Println("❌ FAILURE: Incorrectly accepted wrong message!")
	}

	// Test 5: Test with modified signature
	log.Println("Testing with modified signature...")
	modifiedSig := make([]byte, len(signature))
	copy(modifiedSig, signature)
	modifiedSig[0] ^= 0x01 // Flip one bit

	isValidModified := pubKey.VerifySignature(message, modifiedSig)

	if !isValidModified {
		fmt.Println("✅ SUCCESS: Correctly rejected modified signature!")
	} else {
		fmt.Println("❌ FAILURE: Incorrectly accepted modified signature!")
	}

	// Test 6: Key type and address generation
	fmt.Printf("Private key type: %s\n", privKey.Type())
	fmt.Printf("Public key type: %s\n", pubKey.Type())
	fmt.Printf("Address: %X\n", pubKey.Address())

	fmt.Println("🎉 All basic tests completed!")
}
