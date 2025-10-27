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
	const kaspaAddress = "kaspa:qr0lr4ml9fn3chekrqmjdkergxl93l4wrk3dankcgvjq776s9wn9jkdskewva"

	var prefix, payload, version, err = bech32.Decode(kaspaAddress)

	if err != nil {
		panic("Invalid Bech32 input")
	}

	println("prefix: ", prefix, "\npayload", hex.EncodeToString(payload), "\nversion", version)
}
