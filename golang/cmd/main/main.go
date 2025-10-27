package main

import (
	"encoding/hex"

	"github.com/IzioDev/kaspa-personal-sign-example/v2/utils"
	"github.com/kaspanet/go-secp256k1"
)

func main() {
	// get private key
	sk_bytes, err := hex.DecodeString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")

	if err != nil {
		panic("invalid sk hex")
	}

	keypair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(sk_bytes)
	if err != nil {
		panic("invalid sk")
	}

	println("sk: ", keypair.SerializePrivateKey().String())

	// hash message
	digest := utils.PersonalMessageHash([]byte("hello world"))
	println("message digest: ", hex.EncodeToString(digest[:]))

	var h secp256k1.Hash
	copy(h[:], digest[:])

	// sign message
	serializedSnorrSignature, err := utils.SignPersonal(keypair, digest[:])
	if err != nil {
		panic("error while signing")
	}

	println("signature:", serializedSnorrSignature.String())

	// get signature bytes from hex
	var signature secp256k1.SerializedSchnorrSignature
	_, err = hex.Decode(signature[:], []byte(serializedSnorrSignature.String()))

	// get pk from keypair
	// todo: get it from kaspa address
	pk, err := keypair.SchnorrPublicKey()
	if err != nil {
		panic("failed to get keypair")
	}
	// serialize pk
	serializedPk, err := pk.Serialize()

	// verify signature
	valid, err := utils.VerifyPersonalSchnorr(digest[:], signature[:], serializedPk[:])

	println("is signature valid: ", valid)
}
