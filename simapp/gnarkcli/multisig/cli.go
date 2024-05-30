package main

import (
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/gnarksigner"

	// simple circuit example
	gnarkeddsa "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/multisig_eddsa"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

func main() {

	// setup
	MembersCount := gnarkeddsa.MembersCount
	signer, signBytes, err := gnarksigner.InitSigner()
	if err != nil {
		panic(err)
	}

	//------------------------------------
	// circuit specific

	var msgToSign []byte
	signatures := make([][]byte, MembersCount)
	signed := make([]int, MembersCount)

	for i := 0; i < MembersCount; i++ {
		privkeyFileName := fmt.Sprintf("keys/priv%d", i)
		privBytes, err := os.ReadFile(privkeyFileName)
		if err != nil {
			panic(err)
		}

		// privKey is the hidden bn254 key
		privKey := new(eddsa.PrivateKey)
		privKey.SetBytes(privBytes)

		shouldSign := 1

		// sign with the hidden key and get the hashed msg
		// nil should be replaced with some random signature if shouldSign == 0
		msgBytes, signatureBytes, isSigned := gnarkeddsa.SignMsg(privKey, signBytes, shouldSign, nil)
		signed[i] = isSigned
		signatures[i] = signatureBytes
		msgToSign = msgBytes
	}

	// prepare the witness for zk proof
	privateWitness, publicWitness := gnarkeddsa.PrepareWitness(msgToSign, signatures, MembersCount, signed)

	//------------------------------------

	// sign
	gnarksigner.SignTx(signer, privateWitness, publicWitness)
}
