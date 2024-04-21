package gnark

import (
	"bytes"
	"testing"
)

func TestGnark(t *testing.T) {

	privateKey, publicKey := GenKeys()

	msg := GetMsg()

	signature := SignMsg(privateKey, msg)

	pk, vk, cs := CompileCircuit(publicKey)

	privateWitness, publicWitness := PrepareWitness(msg, signature)

	vkBuf, pkBuf, csBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	vk.WriteTo(vkBuf)
	pk.WriteTo(pkBuf)
	cs.WriteTo(csBuf)

	// marshal the witness
	privWitnessBytes, err := privateWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	verifier := PubKey{vkBuf.Bytes()}
	prover := PrivKey{
		ProvingKey:       pkBuf.Bytes(),
		ConstraintSystem: csBuf.Bytes(),
		VerifyingKey:     vkBuf.Bytes(),
	}

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
