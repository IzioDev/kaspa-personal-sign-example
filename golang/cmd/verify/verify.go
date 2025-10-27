package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/IzioDev/kaspa-personal-sign-example/v2/utils"
)

func main() {
	// Message
	const msgStr = "hello world"

	// Signature: 64-byte Schnorr signature hex (128 hex chars)
	const sigHex = "adff301341a7443c29f56abe17893fb3b0d87b64a9f391948b90c85bc22da115651643eb0fa71d8f40c1cce62a452145dc73119b470e300062e393f55d958682"

	// public key: 32 bytes (64 hex chars)
	const pkHex = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"

	// Decode hex
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		fmt.Println("invalid signature hex:", err)
		os.Exit(1)
	}
	if len(sigBytes) != 64 {
		fmt.Printf("invalid signature length: got %d, want 64 bytes\n", len(sigBytes))
		os.Exit(1)
	}

	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		fmt.Println("invalid public key hex:", err)
		os.Exit(1)
	}
	if len(pkBytes) != 32 {
		fmt.Printf("invalid public key length: got %d, want 32 bytes (x-only)\n", len(pkBytes))
		os.Exit(1)
	}

	// Verify
	ok, err := utils.VerifyPersonalSchnorr([]byte(msgStr), sigBytes, pkBytes)
	if err != nil {
		fmt.Println("verify error:", err)
		os.Exit(1)
	}

	if ok {
		fmt.Println("✅ signature is VALID")
	} else {
		fmt.Println("❌ signature is INVALID")
	}
}
