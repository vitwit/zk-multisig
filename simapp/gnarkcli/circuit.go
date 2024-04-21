package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"
)

// this does the same work as the gnark.TestGnark but it writes
// the eddsa privkey and the circuit bytes to files so we can use them to "sign" transactions.
func main() {

	privateKey, publicKey := gnark.GenKeys()

	pk, vk, cs := gnark.CompileCircuit(publicKey)

	vkBuf, pkBuf, csBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	vk.WriteTo(vkBuf)
	pk.WriteTo(pkBuf)
	cs.WriteTo(csBuf)

	verifier := gnark.PubKey{vkBuf.Bytes()}
	prover := gnark.PrivKey{
		ProvingKey:       pkBuf.Bytes(),
		ConstraintSystem: csBuf.Bytes(),
		VerifyingKey:     verifier.Key,
	}

	ioutil.WriteFile("keys/priv", privateKey.Bytes(), 0666)

	fmt.Println("Hex Account Address", verifier.Address())
	fmt.Printf("Bech32 Account Address: %s\n", sdk.AccAddress(verifier.Address()))

	ioutil.WriteFile("keys/vk", verifier.Key, 0666)
	ioutil.WriteFile("keys/pk", prover.ProvingKey, 0666)
	ioutil.WriteFile("keys/cs", prover.ConstraintSystem, 0666)

	//----

	msg := gnark.GetMsg()

	msgToSign, signature := gnark.SignMsg(privateKey, msg)

	privateWitness, publicWitness := gnark.PrepareWitness(msgToSign, signature)

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

	sig := gnark.Signature{
		ProofBytes:   proofBytes,
		WitnessBytes: pubWitnessBytes,
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
