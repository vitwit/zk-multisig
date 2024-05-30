package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/signature"
	sdk "github.com/cosmos/cosmos-sdk/types"

	// core gnark key types. compiled into SDK binary
	"github.com/cosmos/cosmos-sdk/crypto/keys/gnark"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"

	// example circuit. not compiled into SDK binary
	circuit_eddsa "github.com/consensys/gnark/std/signature/eddsa"
	eddsa "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/multisig_eddsa"
)

var (
	DefaultMsg = []byte("default")
)

// generate an eddsa key, compile the circuit,
// write everything to files so they can be used to sign txs
func main() {

	MembersCount := eddsa.MembersCount
	Threshold := eddsa.Threshold

	// generate the eddsa keys
	pubkeys := make([]signature.PublicKey, MembersCount)
	privkeys := make([]signature.Signer, MembersCount)

	for i := 0; i < MembersCount; i++ {
		privkeys[i], pubkeys[i] = eddsa.GenKeys()
	}

	// get the defaults for circuit internal things
	defaultMsgToSign, defaultSignatures, defaultSignsBytes := DefaultSignatures(privkeys)

	// compile the circuit
	pk, vk, cs := eddsa.CompileCircuit(pubkeys, Threshold, defaultMsgToSign, defaultSignatures)

	vkBuf, pkBuf, csBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	vk.WriteTo(vkBuf)
	pk.WriteTo(pkBuf)
	cs.WriteTo(csBuf)

	verifier := gnark.PubKey{Key: vkBuf.Bytes()}
	prover := gnark.PrivKey{
		ProvingKey:       pkBuf.Bytes(),
		ConstraintSystem: csBuf.Bytes(),
		VerifyingKey:     verifier.Key,
	}

	// write eddsa keys to file
	for i := 0; i < MembersCount; i++ {
		privFileName := fmt.Sprintf("keys/priv%d", i)
		os.WriteFile(privFileName, privkeys[i].Bytes(), 0666)
	}

	// account address is hash(vk)
	fmt.Println("Hex Account Address", verifier.Address())
	bech32Address := sdk.AccAddress(verifier.Address())
	fmt.Printf("Bech32 Account Address: %s\n", bech32Address)
	valoperAddress, err := sdk.Bech32ifyAddressBytes(sdk.Bech32PrefixValAddr, verifier.Address())
	if err != nil {
		panic("couldn't generate validator address" + err.Error())
	}
	fmt.Printf("Validator Address: %s\n", valoperAddress)

	// write circuit keys and data to file
	os.WriteFile("keys/vk", verifier.Key, 0666)
	os.WriteFile("keys/pk", prover.ProvingKey, 0666)
	os.WriteFile("keys/cs", prover.ConstraintSystem, 0666)

	//-----------------------------------------------------------
	// DONE. Circuit is compiled and keys are written to files.
	// What follows is just testing a round of proving/verificaiton.
	//-----------------------------------------------------------

	// get example msg to sign
	msg := gnark.GetMsg()

	signatures := make([][]byte, MembersCount)
	signed := make([]int, MembersCount)

	var msgToSign []byte

	for i := 0; i < MembersCount; i++ {
		toSign := ToSignOrNot()

		msgToSign, signatures[i], signed[i] = eddsa.SignMsg(privkeys[i], msg, toSign, defaultSignsBytes[i])
	}

	fmt.Println("who signed? = ", signed)

	privateWitness, publicWitness := eddsa.PrepareWitness(msgToSign, signatures, MembersCount, signed)

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

// return 0 or 1
func ToSignOrNot() int {
	rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	return rand.Intn(2)
}

// default signatures are used to bypass the check incase of unsigned signature, they held no significance
func DefaultSignatures(privKeys []signature.Signer) ([]byte, []circuit_eddsa.Signature, [][]byte) {
	MembersCount := eddsa.MembersCount
	defaultSignsBytes := make([][]byte, MembersCount)
	defaultSignatures := make([]circuit_eddsa.Signature, MembersCount)

	var defaultMsgToSign []byte

	for i := 0; i < MembersCount; i++ {
		defaultMsgToSign, defaultSignsBytes[i], _ = eddsa.SignMsg(privKeys[i], DefaultMsg, 1, defaultMsgToSign)
	}
	// assign signature values
	for index, signature := range defaultSignsBytes {
		defaultSignatures[index].Assign(tedwards.BN254, signature)
	}

	return defaultMsgToSign, defaultSignatures, defaultSignsBytes
}
