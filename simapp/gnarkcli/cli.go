package main

import (
	"io/ioutil"

	"github.com/cosmos/cosmos-sdk/gnarksigner"

	// simple circuit example
	gnarkeddsa "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/eddsa"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

func main() {

	// setup
	signer, signBytes, err := gnarksigner.InitSigner()
	if err != nil {
		panic(err)
	}

	//------------------------------------
	// circuit specific

	// read in and init the eddsa key. we sign with this key and then prove we did so.
	// this key's address is never revealed on chain!
	privBytes, err := ioutil.ReadFile("keys/priv")
	if err != nil {
		panic(err)
	}

	// privKey is the hidden bn254 key
	privKey := new(eddsa.PrivateKey)
	privKey.SetBytes(privBytes)

	// sign with the hidden key and get the hashed msg
	msgToSign, signatureBytes := gnarkeddsa.SignMsg(privKey, signBytes)

	// prepare the witness for zk proof
	privateWitness, publicWitness := gnarkeddsa.PrepareWitness(msgToSign, signatureBytes)

	//------------------------------------

	// sign
	gnarksigner.SignTx(signer, privateWitness, publicWitness)
}
