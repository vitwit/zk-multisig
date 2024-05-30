package multisig_eddsa

import (
	crand "crypto/rand"
	"fmt"

	// local util
	gnarkutil "github.com/cosmos/cosmos-sdk/crypto/keys/gnark/util"

	// gnark backend and frontend
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// signature
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"

	// twisted edwards
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	// eddsa
	eddsacrypto "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/std/signature/eddsa"

	// hash func
	hash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

// configure this to change the number of members and threshold in multisig
const (
	MembersCount = 6
	Threshold    = 3
)

type MultisigEddsaCircuit struct {
	Message    frontend.Variable `gnark:",public"`
	Signatures []eddsa.Signature
	Signed     []frontend.Variable

	// we use a closure for the Define method so we can hardcode the public key into the circuit
	define func(api frontend.API) error
}

func (circuit *MultisigEddsaCircuit) Define(api frontend.API) error {
	return circuit.define(api)
}

// reutrn the define func as a closure so we can hardcode the public key as part of the circuit
func (circuit *MultisigEddsaCircuit) defineWithPubkey(
	pubkeys []eddsa.PublicKey,
	membersCount uint64,
	threshold int,
	defaultMsg []byte,
	defaultSignatures []eddsa.Signature,
) func(frontend.API) error {
	return func(api frontend.API) error {

		curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
		if err != nil {
			return err
		}

		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}

		api.AssertIsLessOrEqual(threshold, membersCount)
		api.AssertIsEqual(len(pubkeys), membersCount)
		api.AssertIsEqual(len(circuit.Signatures), membersCount)
		api.AssertIsEqual(len(circuit.Signed), membersCount)

		// count the number of valid signatures
		var count frontend.Variable
		count = 0

		for index := 0; index < int(membersCount); index++ {

			pubkey := pubkeys[index]
			sign := SignedOrDefaultSignature(api, circuit.Signed[index], circuit.Signatures[index], defaultSignatures[index])

			msg := api.Select(circuit.Signed[index], circuit.Message, defaultMsg)
			toAdd := api.Select(circuit.Signed[index], 1, 0)

			mimc.Reset()
			eddsa.Verify(curve, sign, msg, pubkey, &mimc)

			count = api.Add(count, toAdd)
		}

		// count should be greater than threshold
		// api.AssertIsLessOrEqual(threshold, count) is not working for some reason
		for i := 0; i < threshold; i++ {
			api.AssertIsDifferent(count, i)
		}

		return nil
	}
}

// if not signed, verify(signature) will throw error
// to avoid that, we will verify some ranom sign just to bypass the error
// Note: this signature won't be counted as valid signature
func SignedOrDefaultSignature(api frontend.API, signed frontend.Variable, sign, defaultSign eddsa.Signature) eddsa.Signature {
	var responseSign eddsa.Signature
	responseSign.R.X = api.Select(signed, sign.R.X, defaultSign.R.X)
	responseSign.R.Y = api.Select(signed, sign.R.Y, defaultSign.R.Y)
	responseSign.S = api.Select(signed, sign.S, defaultSign.S)
	return responseSign
}

// compile circuit hardcodes the pubkeys with the circuit (binding)
func CompileCircuit(publicKeys []signature.PublicKey, threshold int, defaultMsg []byte, defaultSigns []eddsa.Signature) (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem) {
	var circuit MultisigEddsaCircuit

	membersCount := len(publicKeys)
	pubKeys := make([]eddsa.PublicKey, membersCount)

	for i := 0; i < membersCount; i++ {
		_publicKey := publicKeys[i].Bytes()
		pubKeys[i].Assign(tedwards.BN254, _publicKey[:32])
	}

	// using closures to hard code values
	circuit.define = circuit.defineWithPubkey(pubKeys, uint64(membersCount), threshold, defaultMsg, defaultSigns)
	circuit.Signatures = make([]eddsa.Signature, membersCount)
	circuit.Signed = make([]frontend.Variable, membersCount)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	return pk, vk, cs

}

func PrepareWitness(msg []byte, signatures [][]byte, membersCount int, signed []int) (witness.Witness, witness.Witness) {
	// declare the witness
	var assignment MultisigEddsaCircuit

	// assign message value
	assignment.Message = msg
	assignment.Signed = make([]frontend.Variable, membersCount)
	assignment.Signatures = make([]eddsa.Signature, membersCount)

	// assign signature values
	for index, signature := range signatures {
		assignment.Signed[index] = signed[index]
		assignment.Signatures[index].Assign(tedwards.BN254, signature)
	}

	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	return witness, publicWitness

}

func GenKeys() (signature.Signer, signature.PublicKey) {
	// create a eddsa key pair
	privateKey, err := eddsacrypto.New(tedwards.BN254, crand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.Public()

	return privateKey, publicKey
}

// returns msgToSign (msg hashed to curve) and eddsa signature
// shouldSign to check threshold (number of sugnatures doesn't have to equals to number of members)
// default sign doesn't have much meaning, it's there to just bypass the prepare witness panic
func SignMsg(privateKey signature.Signer, msg []byte, shouldSign int, defaultSign []byte) ([]byte, []byte, int) {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()
	msgToSign := gnarkutil.HashMsg(msg)

	if shouldSign == 0 {
		// Todo: rather than sending empty bytes, send some random signature instead!
		return msgToSign, defaultSign, shouldSign
	}

	// sign the message
	signature, err := privateKey.Sign(msgToSign, hFunc)
	if err != nil {
		panic(err)
	}

	// verifies signature
	isValid, err := privateKey.Public().Verify(signature, msgToSign, hFunc)
	if err != nil {
		panic(err)
	}
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}
	return msgToSign, signature, shouldSign
}
