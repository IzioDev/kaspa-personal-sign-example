package utils

import (
	"github.com/kaspanet/go-secp256k1"
	"golang.org/x/crypto/blake2b"
)

var PersonalMessageSigningKey = []byte("PersonalMessageSigningHash")

func PersonalMessageHash(msg []byte) [32]byte {
	h, _ := blake2b.New256(PersonalMessageSigningKey)
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func SignPersonalSchnorr(sk *secp256k1.SchnorrKeyPair, msg []byte) (*secp256k1.SerializedSchnorrSignature, error) {
	digest := PersonalMessageHash(msg)

	var hash secp256k1.Hash
	copy(hash[:], digest[:])

	sig, err := sk.SchnorrSign(&hash)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func SignPersonalECDSA(sk *secp256k1.ECDSAPrivateKey, msg []byte) (*secp256k1.SerializedECDSASignature, error) {
	digest := PersonalMessageHash(msg)

	var hash secp256k1.Hash
	copy(hash[:], digest[:])

	sig, err := sk.ECDSASign(&hash)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

/**
 * msg is the raw message
 * sigBytes is the supposedly signature of the msg
 * pubKeyBytes is the expected signer pubKey
 */
func VerifyPersonalSchnorr(msg []byte, sigBytes, pubKeyBytes []byte) (bool, error) {
	d := PersonalMessageHash(msg)

	var h secp256k1.Hash
	copy(h[:], d[:])

	sig, err := secp256k1.DeserializeSchnorrSignatureFromSlice(sigBytes)
	if err != nil {
		return false, err
	}
	pub, err := secp256k1.DeserializeSchnorrPubKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	ok := pub.SchnorrVerify(&h, sig)
	return ok, nil
}

func VerifyPersonalECDSA(msg []byte, sigBytes, pubKeyBytes []byte) (bool, error) {
	d := PersonalMessageHash(msg)

	var h secp256k1.Hash
	copy(h[:], d[:])

	sig, err := secp256k1.DeserializeECDSASignatureFromSlice(sigBytes)
	if err != nil {
		return false, err
	}
	pub, err := secp256k1.DeserializeECDSAPubKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	ok := pub.ECDSAVerify(&h, sig)
	return ok, nil
}
