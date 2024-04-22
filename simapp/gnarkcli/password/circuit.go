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

func main() {

	pwd := []byte("billysagenius")
	pwdHash := gnarkutil.GetMsgToSign(pwd)

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

	fmt.Println("Hex Account Address", verifier.Address())
	fmt.Printf("Bech32 Account Address: %s\n", sdk.AccAddress(verifier.Address()))

	ioutil.WriteFile("keys/vk", verifier.Key, 0666)
	ioutil.WriteFile("keys/pk", prover.ProvingKey, 0666)
	ioutil.WriteFile("keys/cs", prover.ConstraintSystem, 0666)

	//----

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
