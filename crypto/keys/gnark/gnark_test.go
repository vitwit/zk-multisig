package gnark

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func TestGnark(t *testing.T) {

	privateKey, publicKey := GenKeys()

	msg := GetMsg()

	signature := SignMsg(privateKey, msg)

	pk, vk, cs := CompileCircuit(publicKey)

	privateWitness, publicWitness := PrepareWitness(msg, signature)

	buf := new(bytes.Buffer)
	vk.WriteTo(buf)

	verifier := PubKey{buf.Bytes()}

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
