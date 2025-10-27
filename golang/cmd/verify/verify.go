package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/IzioDev/kaspa-personal-sign-example/v2/utils"
	"github.com/kaspanet/go-secp256k1"
	"github.com/kaspanet/kaspad/util/bech32"
)

func main() {
	// Message
	const msgStr = "hello world"

	// Signature: 64-byte signature hex (128 hex chars)
	const sigHex = "35c5efc9c4a87df63301fa0e51cb29e1417676ed798486e7e5bf7fb413bdbfa3549ecb811636a31363c13fea5393202f657d020f1ee1976bef55f7386f6ace65"

	// kaspa address
	const kaspaAddress = "kaspa:qr0lr4ml9fn3chekrqmjdkergxl93l4wrk3dankcgvjq776s9wn9jkdskewva"

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

	prefix, pkBytes, version, err := bech32.Decode(kaspaAddress)
	fmt.Println("DEBUG: ", prefix, pkBytes, version)
	if err != nil {
		fmt.Println("invalid Kaspa address:", err)
		os.Exit(1)
	}

	if version != 0 && version != 1 {
		fmt.Println("expected bech32 version 0 or 1, found:", version)
		panic("")
	}

	if version == 0 && len(pkBytes) != 32 {
		fmt.Printf("invalid schnorr public key length: got %d, want 32 bytes \n", len(pkBytes))
		os.Exit(1)
	}

	if version == 1 && len(pkBytes) != 33 {
		fmt.Printf("invalid ecdsa public key length: got %d, want 33 bytes \n", len(pkBytes))
		os.Exit(1)
	}

	fmt.Println("bech32 prefix: ", prefix, " version: ", version)
	var ok bool

	if version == 0 {

		// get signature bytes from hex
		var signature secp256k1.SerializedSchnorrSignature
		_, err = hex.Decode(signature[:], []byte(sigHex))

		// Verify using Schnorr
		ok, err = utils.VerifyPersonalSchnorr([]byte(msgStr), signature[:], pkBytes)
		if err != nil {
			fmt.Println("verify error:", err)
			os.Exit(1)
		}

		if ok {
			fmt.Println("✅ Schnorr signature is VALID")
		} else {
			fmt.Println("❌ Schnorr signature is INVALID")
		}
	}

	if version == 1 {
		// Verify using ECDSA
		ok, err = utils.VerifyPersonalECDSA([]byte(msgStr), sigBytes, pkBytes)
		if err != nil {
			fmt.Println("verify error:", err)
			os.Exit(1)
		}

		if ok {
			fmt.Println("✅ ECDSA signature is VALID")
		} else {
			fmt.Println("❌ ECDSA signature is INVALID")
		}
	}

}
