package main

import (
	"bytes"
	"fmt"

	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"
)

func main() {

	privateKey, publicKey := gnark.GenKeys()

	msg := gnark.GetMsg()

	signature := gnark.SignMsg(privateKey, msg)

	pk, vk, cs := gnark.CompileCircuit(publicKey)

	privateWitness, publicWitness := gnark.PrepareWitness(msg, signature)

	vkBuf, pkBuf, csBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	vk.WriteTo(vkBuf)
	pk.WriteTo(pkBuf)
	cs.WriteTo(csBuf)

	// marshal the witness
	privWitnessBytes, err := privateWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	verifier := gnark.PubKey{vkBuf.Bytes()}
	prover := gnark.PrivKey{
		ProvingKey:       pkBuf.Bytes(),
		ConstraintSystem: csBuf.Bytes(),
		VerifyingKey:     verifier.Key,
	}

	fmt.Println("Address", verifier.Address())

	proofBytes, err := prover.Sign(privWitnessBytes)
	if err != nil {
		panic(err)
	}

	// marshal the witness
	pubWitnessBytes, err := publicWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	valid := verifier.VerifySignature(pubWitnessBytes, proofBytes)
	if !valid {
		panic("invalid sig")
	}
}
