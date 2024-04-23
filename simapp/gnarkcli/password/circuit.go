package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	sdk "github.com/cosmos/cosmos-sdk/types"

	// core gnark key types. compiled into SDK binary
	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"
	gnarkutil "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/util"

	// example circuit. not compiled into SDK binary
	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark/password"
)

// compile circuit using given password,
// write everything to files so they can be used to sign txs
func main() {

	// our super secret password
	pwd := []byte("billysagenius")
	pwdHash := gnarkutil.HashMsg(pwd)

	// compile the circuit
	pk, vk, cs := password.CompileCircuit(pwdHash)

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

	// account address is hash(vk)
	fmt.Println("Hex Account Address", verifier.Address())
	fmt.Printf("Bech32 Account Address: %s\n", sdk.AccAddress(verifier.Address()))

	// write circuit keys and data to file
	ioutil.WriteFile("keys/vk", verifier.Key, 0666)
	ioutil.WriteFile("keys/pk", prover.ProvingKey, 0666)
	ioutil.WriteFile("keys/cs", prover.ConstraintSystem, 0666)

	//-----------------------------------------------------------
	// DONE. Circuit is compiled and keys are written to files.
	// What follows is just testing a round of proving/verificaiton.
	//-----------------------------------------------------------

	// get example msg to sign
	msg := gnark.GetMsg()

	msgToSign, signature := password.SignMsg(pwd, msg)

	privateWitness, publicWitness := password.PrepareWitness(msgToSign, signature)

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
