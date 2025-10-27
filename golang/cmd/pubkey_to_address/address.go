package main

import (
	"encoding/hex"

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

	// 0 for schnorr, 1 for ecdsa
	var encoded = bech32.Encode("kaspa", pkBytes, 0)

	print("encoded ", encoded)
}
