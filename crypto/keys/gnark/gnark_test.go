package gnark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func TestGnark(t *testing.T) {

	privateKey, publicKey := GenKeys()

	pk, vk, cs := CompileCircuit(publicKey)

	vkBuf, pkBuf, csBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	vk.WriteTo(vkBuf)
	pk.WriteTo(pkBuf)
	cs.WriteTo(csBuf)

	verifier := PubKey{vkBuf.Bytes()}
	prover := PrivKey{
		ProvingKey:       pkBuf.Bytes(),
		ConstraintSystem: csBuf.Bytes(),
		VerifyingKey:     vkBuf.Bytes(),
	}

	msg := GetMsg()
	fmt.Println(msg)
	fmt.Println(len(msg))

	msgToSign, signature := SignMsg(privateKey, msg)

	privateWitness, publicWitness := PrepareWitness(msgToSign, signature)

	// marshal the witness
	privWitnessBytes, err := privateWitness.MarshalBinary()
	if err != nil {
		panic(err)
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

	sig := Signature{
		ProofBytes:   proofBytes,
		WitnessBytes: pubWitnessBytes,
		/*EddsaSignature: signature,
		Message:        msgToSign,*/
	}

	sigBytes, err := json.Marshal(sig)
	if err != nil {
		panic(err)
	}

	valid := verifier.VerifySignature(msg, sigBytes)
	if !valid {
		panic("invalid sig")
	}
}
