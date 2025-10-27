package main

import (
	"encoding/hex"
	"fmt"

	"github.com/IzioDev/kaspa-personal-sign-example/v2/utils"
	"github.com/kaspanet/go-secp256k1"
)

// 0 for schnorr, 1 for ecdsa
const version = 0

func main() {
	const msgStr = "hello world"

	// get private key
	sk_bytes, err := hex.DecodeString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")

	if err != nil {
		panic("invalid sk hex")
	}

	// SCHNORR
	if version == 0 {
		keypair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(sk_bytes)
		if err != nil {
			panic("invalid sk")
		}

		schnorrPk, err := keypair.SchnorrPublicKey()
		if err != nil {
			fmt.Println("Error: ", err)
			panic("")
		}

		println("sk: ", keypair.SerializePrivateKey().String(), "pk: ", schnorrPk.String())

		// sign message
		serializedSnorrSignature, err := utils.SignPersonalSchnorr(keypair, []byte(msgStr))
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
		valid, err := utils.VerifyPersonalSchnorr([]byte(msgStr), signature[:], serializedPk[:])

		println("is signature valid: ", valid)
	}

	// ECDSA
	if version == 1 {
		ecdsaSk, err := secp256k1.DeserializeECDSAPrivateKeyFromSlice(sk_bytes)
		if err != nil {
			panic("invalid sk")
		}

		ecdsaPk, err := ecdsaSk.ECDSAPublicKey()
		if err != nil {
			fmt.Println("Error: ", err)
			panic("")
		}

		println("sk: ", ecdsaSk.Serialize().String(), "pk: ", ecdsaPk.String())

		// sign message
		serializedSnorrSignature, err := utils.SignPersonalECDSA(ecdsaSk, []byte(msgStr))
		if err != nil {
			panic("error while signing")
		}

		println("signature:", serializedSnorrSignature.String())

		// get signature bytes from hex
		var signature secp256k1.SerializedSchnorrSignature
		_, err = hex.Decode(signature[:], []byte(serializedSnorrSignature.String()))

		// get pk from keypair
		// todo: get it from kaspa address
		pk, err := ecdsaSk.ECDSAPublicKey()
		if err != nil {
			panic("failed to get keypair")
		}
		// serialize pk
		serializedPk, err := pk.Serialize()

		// verify signature
		valid, err := utils.VerifyPersonalECDSA([]byte(msgStr), signature[:], serializedPk[:])

		println("is signature valid: ", valid)
	}
}
