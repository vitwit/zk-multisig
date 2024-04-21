package main

import (
	"bytes"
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"

	"github.com/consensys/gnark/backend/groth16"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func main() {

	privateKey, publicKey := gnark.GenKeys()

	msg := gnark.GetMsg()

	signature := gnark.SignMsg(privateKey, msg)

	pk, vk, cs := gnark.CompileCircuit(publicKey)

	privateWitness, publicWitness := gnark.PrepareWitness(msg, signature)

	buf := new(bytes.Buffer)
	vk.WriteTo(buf)

	verifier := gnark.PubKey{buf.Bytes()}

	// generate the proof
	proof, err := groth16.Prove(cs, pk, privateWitness)
	if err != nil {
		panic(err)
	}

	// marshal the proof
	proofbn254 := proof.(*bn254.Proof)
	proofBytes, err := json.Marshal(proofbn254)
	if err != nil {
		panic(err)
	}

	// marshal the witness
	witnessBytes, err := publicWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	valid := verifier.VerifySignature(witnessBytes, proofBytes)
	if !valid {
		panic("invalid sig")
	}
}
