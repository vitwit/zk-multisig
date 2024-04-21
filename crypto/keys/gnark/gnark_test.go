package gnark

import (
	"bytes"
	"encoding/json"
	"testing"

	// use the example eddsa circuit
	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark/eddsa"
)

func TestGnark(t *testing.T) {

	privateKey, publicKey := eddsa.GenKeys()

	pk, vk, cs := eddsa.CompileCircuit(publicKey)

	// get the byte representation of the circuit
	vkBuf, pkBuf, csBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	vk.WriteTo(vkBuf)
	pk.WriteTo(pkBuf)
	cs.WriteTo(csBuf)

	// build the verifier (pubkey) and prover (privkey) from the bytes
	verifier := PubKey{vkBuf.Bytes()}
	prover := PrivKey{
		ProvingKey:       pkBuf.Bytes(),
		ConstraintSystem: csBuf.Bytes(),
		VerifyingKey:     vkBuf.Bytes(),
	}

	// get a standard msg
	msg := GetMsg()

	// eddsa sign it
	msgToSign, signature := eddsa.SignMsg(privateKey, msg)

	// prepare witness of the msg signed and signature
	privateWitness, publicWitness := eddsa.PrepareWitness(msgToSign, signature)

	// marshal the priv witness for proving
	privWitnessBytes, err := privateWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// produce zk proof
	proofBytes, err := prover.Sign(privWitnessBytes)
	if err != nil {
		panic(err)
	}

	// marshal the pub witness for verifying
	pubWitnessBytes, err := publicWitness.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// "signature" contains the proof bytes and witness bytes
	sig := Signature{
		ProofBytes:   proofBytes,
		WitnessBytes: pubWitnessBytes,
	}

	sigBytes, err := json.Marshal(sig)
	if err != nil {
		panic(err)
	}

	// verify zk proof
	valid := verifier.VerifySignature(msg, sigBytes)
	if !valid {
		panic("invalid sig")
	}
}
