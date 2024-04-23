package eddsa

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

//------------
// the circuit is defined independelty of the PubKey and PrivKey implementation
//
// however there is one requirement: the circuit struct (witness) MUST begin with the Message (hash of the tx signBytes).
// this is because the message in the circuit witness can only be a single field element,
// but we need to pass in the full tx bytes in VerifySignature, so we need to be able to check
// the hash of the tx bytes equal the Message in the witness. Since we don't want to depend directly on the witness structure (it could be an arbitrary circuit)
// we just require the first element in the witness is the Message so we can at least fetch that.

// TODO: write other example circuits

type eddsaCircuit struct {
	Message   frontend.Variable `gnark:",public"`
	Signature eddsa.Signature

	// we use a closure for the Define method so we can hardcode the public key into the circuit
	define func(api frontend.API) error
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	return circuit.define(api)
}

// reutrn the define func as a closure so we can hardcode the public key as part of the circuit
func (circuit *eddsaCircuit) defineWithPubkey(pubkey eddsa.PublicKey) func(frontend.API) error {
	return func(api frontend.API) error {
		curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
		if err != nil {
			return err
		}

		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		// verify the signature in the cs
		return eddsa.Verify(curve, circuit.Signature, circuit.Message, pubkey, &mimc)
	}
}

func CompileCircuit(publicKey signature.PublicKey) (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem) {
	var circuit eddsaCircuit

	// assign public key values
	// fixed pubkey should be part of circuit
	var pubKey eddsa.PublicKey
	_publicKey := publicKey.Bytes()
	pubKey.Assign(tedwards.BN254, _publicKey[:32])
	circuit.define = circuit.defineWithPubkey(pubKey)

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

func PrepareWitness(msg, signature []byte) (witness.Witness, witness.Witness) {
	// declare the witness
	var assignment eddsaCircuit

	// assign message value
	assignment.Message = msg

	// assign signature values
	assignment.Signature.Assign(tedwards.BN254, signature)

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
func SignMsg(privateKey signature.Signer, msg []byte) ([]byte, []byte) {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	msgToSign := gnarkutil.HashMsg(msg)

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
	return msgToSign, signature
}
