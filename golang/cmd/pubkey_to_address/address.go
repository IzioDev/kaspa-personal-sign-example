package main

import (
	"encoding/hex"
	"fmt"

	"github.com/kaspanet/kaspad/util/bech32"
)

// version
// 0 = schnorr
// 1 = ecdsa
// 8 = script hash

func main() {
	// public key: 32 bytes (64 hex chars)
	const pkHex = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"

	var pkBytes, err = hex.DecodeString(pkHex)

	if err != nil {
		panic("invalid pk hex")
	}

	if len(pkBytes) != 32 && len(pkBytes) != 33 {
		fmt.Println("expected length or 32 (schnorr) or 33 (ecdsa) for payload, got:", len(pkBytes))
		panic("")
	}

	if len(pkBytes) == 32 {
		// 0 for schnorr, 1 for ecdsa
		var encoded = bech32.Encode("kaspa", pkBytes, 0)

		print("encoded (schnorr):  ", encoded)
	}

	if len(pkBytes) == 33 {
		// 0 for schnorr, 1 for ecdsa
		var encoded = bech32.Encode("kaspa", pkBytes, 1)

		print("encoded (ecdsa):  ", encoded)
	}
}
