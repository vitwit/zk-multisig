package main

import (
	"github.com/cosmos/cosmos-sdk/gnarksigner"

	// simple circuit example
	password "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/password"
)

func main() {

	signer, signBytes, err := gnarksigner.InitSigner()
	if err != nil {
		panic(err)
	}

	//---------------
	// circuit specific

	pwd := []byte("billysagenius")

	// sign with the hidden key and get the hashed msg
	msgToSign, signatureBytes := password.SignMsg(pwd, signBytes)

	// prepare the witness for zk proof
	privateWitness, publicWitness := password.PrepareWitness(msgToSign, signatureBytes)

	//--------

	gnarksigner.SignTx(signer, privateWitness, publicWitness)
}
